pub struct Singleflight<K, T>
where
    K: std::cmp::Eq + std::hash::Hash,
    T: Clone + Send + 'static,
{
    tasks:
        std::sync::Arc<parking_lot::RwLock<std::collections::HashMap<K, std::sync::Weak<Task<T>>>>>,
}

struct Task<T>
where
    T: Clone + Send + 'static,
{
    notify: tokio::sync::Notify,
    result: once_cell::race::OnceBox<parking_lot::Mutex<T>>,
}

impl<K, T> Default for Singleflight<K, T>
where
    K: std::cmp::Eq + std::hash::Hash,
    T: Clone + Send + 'static,
{
    fn default() -> Self {
        Singleflight::new()
    }
}

impl<K, T> Clone for Singleflight<K, T>
where
    K: std::cmp::Eq + std::hash::Hash,
    T: Clone + Send + 'static,
{
    fn clone(&self) -> Self {
        Singleflight {
            tasks: self.tasks.clone(),
        }
    }
}

impl<K, T> Singleflight<K, T>
where
    K: std::cmp::Eq + std::hash::Hash,
    T: Clone + Send + 'static,
{
    pub fn new() -> Singleflight<K, T> {
        Singleflight {
            tasks: Default::default(),
        }
    }

    pub async fn request<W, F>(&self, key: K, work: W) -> T
    where
        W: FnOnce() -> F,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let maybe_task = {
            let tasks = self.tasks.read();
            match tasks.get(&key) {
                Some(t) => t.upgrade(),
                None => None,
            }
        };

        let task = match maybe_task {
            Some(task) => task,
            None => {
                let mut tasks = self.tasks.write();
                let maybe_task = match tasks.get(&key) {
                    Some(t) => t.upgrade(),
                    None => None,
                };
                match maybe_task {
                    Some(t) => t,
                    None => {
                        let fut = FutureCapturingIntoMutex(Box::pin(work()));
                        let task = std::sync::Arc::new(Task {
                            notify: tokio::sync::Notify::new(),
                            result: once_cell::race::OnceBox::new(),
                        });

                        tasks.insert(key, std::sync::Arc::downgrade(&task));

                        // Run the given future in a dedicated tokio task to ensure completion.
                        // This is required because downstream withdraws their request without
                        // waiting completion, and it never completes if they repeats to do so.
                        let handle = tokio::spawn(ensure_completion(task.clone(), fut));
                        tokio::spawn(panic_protection(task.clone(), handle));

                        task
                    }
                }
            }
        };
        let wait = task.notify.notified();
        if let Some(v) = task.result.get() {
            let value = v.lock();
            return value.clone();
        }
        wait.await;
        let v = task
            .result
            .get()
            .expect("value was empty - perhaps task has panicked");
        let value = v.lock();
        value.clone()
    }
}

impl<K, T> std::fmt::Debug for Singleflight<K, T>
where
    K: std::cmp::Eq + std::hash::Hash,
    T: Clone + Send + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Singleflight").finish()
    }
}

struct FutureCapturingIntoMutex<T: Clone + Send + 'static>(
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'static>>,
);

impl<T> std::future::Future for FutureCapturingIntoMutex<T>
where
    T: Clone + Send + 'static,
{
    type Output = parking_lot::Mutex<T>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let up = self.0.as_mut();
        match up.poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(v) => std::task::Poll::Ready(parking_lot::Mutex::new(v)),
        }
    }
}

async fn ensure_completion<T>(task: std::sync::Arc<Task<T>>, fut: FutureCapturingIntoMutex<T>)
where
    T: Clone + Send,
{
    let value = fut.await;
    let r = task.result.set(Box::new(value));
    if r.is_err() {
        panic!("value was full");
    }
    task.notify.notify_waiters();
}

async fn panic_protection<T>(task: std::sync::Arc<Task<T>>, handle: tokio::task::JoinHandle<()>)
where
    T: Clone + Send + 'static,
{
    let result = handle.await;
    if let Err(e) = result {
        task.notify.notify_waiters();
        if e.is_panic() {
            std::panic::resume_unwind(e.into_panic());
        }
        panic!("task aborted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single() {
        let group = Singleflight::new();
        let result = group.request("aa".to_string(), || async { Some(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }
    #[tokio::test]
    async fn multi() {
        let group = Singleflight::new();
        let result0 = group.request("aa".to_string(), || async { Some(42) }).await;
        let result1 = group.request("aa".to_string(), || async { Some(43) }).await;
        assert_eq!(result0.unwrap(), 42);
        assert_eq!(result1.unwrap(), 43);
    }

    #[tokio::test]
    #[should_panic]
    async fn panic() {
        let group = Singleflight::<String, ()>::new();
        group.request("aa".to_string(), || async { panic!() }).await;
    }

    #[tokio::test]
    async fn collapsing() {
        let group = Singleflight::<String, u32>::new();

        let (tx, rx) = tokio::sync::oneshot::channel();

        let fut0 = group.request("a".to_string(), || async move {
            rx.await.ok();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            42
        });
        let fut1 = group.request("a".to_string(), || async { 0 });
        let fut2 = group.request("a".to_string(), || async { 1 });

        let fut3 = group.request("b".to_string(), || async { 420 });

        let r2 = fut2.await; // As we haven't polled fut0,fut1 yet, this should complete instantly

        let fut_dummy = async move {
            tx.send(()).unwrap();
            0
        };
        let (r0, r1, r3, _dummy) = tokio::join!(fut0, fut1, fut3, fut_dummy);

        assert_eq!((r0, r1), (42, 42));
        assert_eq!(r2, 1);
        assert_eq!(r3, 420);

        let fut4 = group.request("a".to_string(), || async { 2 });
        assert_eq!(fut4.await, 2);
    }

    #[tokio::test]
    async fn ensuring_completion() {
        let group = Singleflight::<String, u32>::new();
        let (req_tx, req_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let req = group.request("a".to_string(), move || async move {
                req_rx.await.unwrap();
                resp_tx.send(42).unwrap();
                0
            });
            ready_tx.send(()).unwrap();
            tokio::select! {
                _ = cancel_rx => {},
                _ = req => { unreachable!() },
            }
            drop_tx.send(()).unwrap();
        });

        ready_rx.await.unwrap();
        cancel_tx.send(()).unwrap();
        drop_rx.await.unwrap();
        req_tx.send(42).expect("req_rx was gone");
        assert_eq!(resp_rx.await.unwrap(), 42);
    }
}
