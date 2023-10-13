pub struct Singleflight<T>
where
    T: Clone + Send + 'static,
{
    tasks: std::sync::Arc<
        parking_lot::RwLock<std::collections::HashMap<String, std::sync::Weak<Task<T>>>>,
    >,
}

struct Task<T>
where
    T: Clone + Send + 'static,
{
    notify: tokio::sync::Notify,
    result: once_cell::race::OnceBox<parking_lot::Mutex<T>>,
}

impl<T> Default for Singleflight<T>
where
    T: Clone + Send + 'static,
{
    fn default() -> Self {
        Singleflight::new()
    }
}

impl<T> Clone for Singleflight<T>
where
    T: Clone + Send + 'static,
{
    fn clone(&self) -> Self {
        Singleflight {
            tasks: self.tasks.clone(),
        }
    }
}

impl<T> Singleflight<T>
where
    T: Clone + Send + 'static,
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
                task
            }
            None => {
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
                tokio::spawn(ensure_completion(task.clone(), fut));

                task
            }
        };
        let wait = task.notify.notified();
        if let Some(v) = task.result.get() {
            let value = v.lock();
            return value.clone();
        }
        wait.await;
        let v = task.result.get().expect("value was empty");
        let value = v.lock();
        value.clone()
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
        panic!("value was full")
    }
    task.notify.notify_waiters();
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
        let result1 = group.request("aa".to_string(), || async { panic!() }).await;
        assert_eq!(result0.unwrap(), 42);
        assert_eq!(result1.unwrap(), 42);
    }
}
