pub struct Singleflight<T>
where
    T: Clone + Send + std::fmt::Debug + 'static,
{
    tasks: std::sync::Arc<
        parking_lot::RwLock<std::collections::HashMap<String, std::sync::Weak<Task<T>>>>,
    >,
}

struct Task<T>
where
    T: Clone + Send + std::fmt::Debug + 'static,
{
    notify: tokio::sync::Notify,
    result: once_cell::race::OnceBox<parking_lot::Mutex<T>>,
}

impl<T> Default for Singleflight<T>
where
    T: Clone + Send + std::fmt::Debug + 'static,
{
    fn default() -> Self {
        Singleflight::new()
    }
}

impl<T> Clone for Singleflight<T>
where
    T: Clone + Send + std::fmt::Debug + 'static,
{
    fn clone(&self) -> Self {
        Singleflight {
            tasks: self.tasks.clone(),
        }
    }
}

impl<T> Singleflight<T>
where
    T: Clone + Send + std::fmt::Debug + 'static,
{
    pub fn new() -> Singleflight<T> {
        Singleflight {
            tasks: Default::default(),
        }
    }

    pub async fn request<W, F>(&self, key: String, work: W) -> T
    where
        W: FnOnce() -> F,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let tasks = self.tasks.upgradable_read();
        let maybe_task = match tasks.get(&key) {
            Some(t) => t.upgrade(),
            None => None,
        };

        let task = match maybe_task {
            Some(task) => {
                drop(tasks);
                eprintln!("reusing task");
                task
            }
            None => {
                eprintln!("new task");
                let fut = FutureCapturingIntoMutex(Box::pin(work()));
                let task = std::sync::Arc::new(Task {
                    notify: tokio::sync::Notify::new(),
                    result: once_cell::race::OnceBox::new(),
                });

                {
                    let mut tasks = parking_lot::RwLockUpgradableReadGuard::upgrade(tasks);
                    tasks.insert(key.to_owned(), std::sync::Arc::downgrade(&task));
                }

                // Ensure the given future to complete
                let handle = tokio::spawn(ensure_completion(task.clone(), fut));
                tokio::spawn(panic_protection(task.clone(), handle));

                task
            }
        };
        eprintln!("subscribing");
        let wait = task.notify.notified();
        if let Some(v) = task.result.get() {
            eprintln!("no need to wait");
            let value = v.lock();
            return value.clone();
        }
        eprintln!("waiting");
        wait.await;
        eprintln!("notified");
        let v = task
            .result
            .get()
            .expect("value was empty - perhaps task has panicked");
        let value = v.lock();
        value.clone()
    }
}

struct FutureCapturingIntoMutex<T: Clone + Send + std::fmt::Debug + 'static>(
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'static>>,
);

impl<T> std::future::Future for FutureCapturingIntoMutex<T>
where
    T: Clone + Send + std::fmt::Debug + 'static,
{
    type Output = parking_lot::Mutex<T>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let up = self.0.as_mut();
        eprintln!("FutureCapturingIntoMutex is polled");
        match up.poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(v) => {
                eprintln!("FutureCapturingIntoMutex is ready");
                std::task::Poll::Ready(parking_lot::Mutex::new(v))
            }
        }
    }
}

async fn ensure_completion<T>(task: std::sync::Arc<Task<T>>, fut: FutureCapturingIntoMutex<T>)
where
    T: Clone + Send + std::fmt::Debug,
{
    eprintln!("spawned");
    let value = fut.await;
    eprintln!("completed {value:?}");
    let r = task.result.set(Box::new(value));
    if r.is_err() {
        panic!("value was full");
    }
    task.notify.notify_waiters();
}

async fn panic_protection<T>(task: std::sync::Arc<Task<T>>, handle: tokio::task::JoinHandle<()>)
where
    T: Clone + Send + std::fmt::Debug + 'static,
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
        let group = Singleflight::<()>::new();
        group.request("aa".to_string(), || async { panic!() }).await;
    }

    #[tokio::test]
    async fn collapsing() {
        let group = Singleflight::new();

        let (tx, rx) = tokio::sync::oneshot::channel();

        eprintln!("fut0");
        let fut0 = group.request("a".to_string(), || async move {
            eprintln!("spawned inner");
            rx.await.ok();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            eprintln!("returning value");
            42
        });
        eprintln!("fut1");
        let fut1 = group.request("a".to_string(), || async { 0 });
        eprintln!("fut2");
        let fut2 = group.request("a".to_string(), || async { 1 });

        eprintln!("fut3");
        let fut3 = group.request("b".to_string(), || async { 420 });

        let r2 = fut2.await; // As we haven't polled fut0,fut1 yet, this should complete instantly

        let fut_dummy = async move {
            eprintln!("tx.send");
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
}
