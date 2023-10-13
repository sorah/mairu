pub struct Singleflight<T>
where
    T: Clone + Send + 'static,
    //    F: std::future::Future<Output = T> + Send + 'static,
{
    tasks: std::sync::Arc<
        parking_lot::RwLock<std::collections::HashMap<String, std::sync::Weak<Task<T>>>>,
    >,
}

#[pin_project::pin_project]
struct Task<T>
where
    T: Clone + Send + 'static,
    //    F: std::future::Future<Output = T> + Send + 'static,
{
    #[pin]
    result: async_once_cell::Lazy<
        parking_lot::Mutex<T>,
        //std::pin::Pin<Box<dyn std::future::Future<Output = parking_lot::Mutex<T>>>>,
        //FutureCapturingIntoMutex<std::pin::Pin<Box<F>>>,
        FutureCapturingIntoMutex<T>,
    >,
}

impl<T> Default for Singleflight<T>
where
    T: Clone + Send + 'static,
    //    F: std::future::Future<Output = T> + Send + 'static,
{
    fn default() -> Self {
        Singleflight::new()
    }
}

impl<T> Clone for Singleflight<T>
where
    T: Clone + Send + 'static,
    //    F: std::future::Future<Output = T> + Send + 'static,
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
    //    F: std::future::Future<Output = T> + Send + 'static,
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
                let lazy = async_once_cell::Lazy::new(FutureCapturingIntoMutex(Box::pin(work())));
                let task = std::sync::Arc::new(Task { result: lazy });

                {
                    let mut tasks = parking_lot::RwLockUpgradableReadGuard::upgrade(tasks);
                    tasks.insert(key.to_owned(), std::sync::Arc::downgrade(&task));
                }

                // Ensure the given future to complete
                tokio::spawn(ensure_completion(
                    //self.clone(),
                    //key.to_owned(),
                    task.clone(),
                ));

                task
            }
        };
        let r = task.result.as_ref();
        let val = r.get().await;
        let lock = val.get_ref().lock();
        lock.clone()
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
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let up = self.0.as_mut();
        match up.poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(v) => std::task::Poll::Ready(parking_lot::Mutex::new(v)),
        }
    }
}

async fn ensure_completion<T>(
    //    group: Singleflight<T, F>,
    //    k: String,
    task: std::sync::Arc<Task<T>>,
) where
    T: Clone + Send,
{
    let t = task.as_ref();
    tokio::pin!(t);
    t.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single() {
        let group = Singleflight::new();
        let result = group.request("aa".to_string(), async { Some(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }
    #[tokio::test]
    async fn multi() {
        let group = Singleflight::new();
        let result0 = group.request("aa".to_string(), async { Some(42) }).await;
        let result1 = group.request("aa".to_string(), async { Some(42) }).await;
        assert_eq!(result0.unwrap(), 42);
        assert_eq!(result1.unwrap(), 42);
    }
}
