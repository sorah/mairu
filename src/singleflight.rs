pub struct Singleflight<T, F>
where
    T: Clone + Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    tasks: std::sync::Arc<parking_lot::RwLock<std::collections::HashMap<String, Task<T, F>>>>,
}

#[derive(Clone)]
struct Task<T, F>
where
    T: Clone + Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    inner: std::sync::Weak<TaskInner<T, F>>,
}

struct TaskInner<T, F>
where
    T: Clone + Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    result: std::pin::Pin<
        Box<
            async_once_cell::Lazy<
                parking_lot::Mutex<T>,
                //std::pin::Pin<Box<dyn std::future::Future<Output = parking_lot::Mutex<T>>>>,
                //FutureCapturingIntoMutex<std::pin::Pin<Box<F>>>,
                FutureCapturingIntoMutex<F>,
            >,
        >,
    >,
}

impl<T, F> Default for Singleflight<T, F>
where
    T: Clone + Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    fn default() -> Self {
        Singleflight::new()
    }
}

impl<T, F> Clone for Singleflight<T, F>
where
    T: Clone + Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    fn clone(&self) -> Self {
        Singleflight {
            tasks: self.tasks.clone(),
        }
    }
}

impl<T, F> Singleflight<T, F>
where
    T: Clone + Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    pub fn new() -> Singleflight<T, F> {
        Singleflight {
            tasks: Default::default(),
        }
    }

    pub async fn request(&self, key: String, fut: F) -> T {
        let tasks = self.tasks.upgradable_read();
        let maybe_task = match tasks.get(&key) {
            Some(t) => t.inner.upgrade(),
            None => None,
        };

        let task = match maybe_task {
            Some(task) => {
                drop(tasks);
                task
            }
            None => {
                let lazy = Box::pin(async_once_cell::Lazy::new(FutureCapturingIntoMutex(fut)));
                let task = std::sync::Arc::new(TaskInner { result: lazy });

                {
                    let mut tasks = parking_lot::RwLockUpgradableReadGuard::upgrade(tasks);
                    let task_outer = Task {
                        inner: std::sync::Arc::downgrade(&task),
                    };
                    tasks.insert(key.to_owned(), task_outer);
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

#[pin_project::pin_project]
struct FutureCapturingIntoMutex<F: std::future::Future + Send>(#[pin] F);

impl<F> std::future::Future for FutureCapturingIntoMutex<F>
where
    F: std::future::Future + Send,
{
    type Output = parking_lot::Mutex<F::Output>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        let up: std::pin::Pin<&mut F> = this.0;
        match up.poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(v) => std::task::Poll::Ready(parking_lot::Mutex::new(v)),
        }
    }
}

async fn ensure_completion<T, F>(
    //    group: Singleflight<T, F>,
    //    k: String,
    t: std::sync::Arc<TaskInner<T, F>>,
) where
    T: Clone + Send,
    F: std::future::Future<Output = T> + Send,
{
    let r = &t.result.as_ref();
    r.get().await;
    //    let mut tasks = group.tasks.write();
    //    tasks.remove(&k);
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
