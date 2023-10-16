pub struct Singleflight<'a, T>
where
    T: Clone + Send + 'static,
{
    tasks: std::sync::Arc<
        parking_lot::RwLock<std::collections::HashMap<String, std::sync::Weak<Task<'a, T>>>>,
    >,
}

struct Task<'a, T>
where
    T: Clone + Send + 'static,
{
    notify: tokio::sync::Notify,
    result: once_cell::race::OnceBox<parking_lot::Mutex<T>>,
    phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a, T> Default for Singleflight<'a, T>
where
    T: Clone + Send + 'static,
{
    fn default() -> Self {
        Singleflight::new()
    }
}

impl<'a, T> Clone for Singleflight<'a, T>
where
    T: Clone + Send + 'static,
{
    fn clone(&self) -> Self {
        Singleflight {
            tasks: self.tasks.clone(),
        }
    }
}

impl<'a, T> Singleflight<'a, T>
where
    T: Clone + Send + 'static,
{
    pub fn new() -> Singleflight<'a, T> {
        Singleflight {
            tasks: Default::default(),
        }
    }

    pub fn request<W, F>(&self, key: String, work: W) -> RequestHandle<'_, T>
    where
        W: FnOnce() -> F,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let task = self.request_prepare(key, work);
        RequestHandle {
            inner: RequestHandleInner::Pending(task),
        }
    }

    fn request_prepare<W, F>(&self, key: String, work: W) -> std::sync::Arc<Task<T>>
    where
        W: FnOnce() -> F,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let tasks = self.tasks.upgradable_read();
        let maybe_task = match tasks.get(&key) {
            Some(t) => {
                eprintln!("trying upgrade");
                t.upgrade()
            }
            None => None,
        };

        match maybe_task {
            Some(task) => {
                eprintln!("there is a task");
                drop(tasks);
                task
            }
            None => {
                eprintln!("new task");
                let fut = FutureCapturingIntoMutex(Box::pin(work()));
                let task = std::sync::Arc::new(Task {
                    notify: tokio::sync::Notify::new(),
                    result: once_cell::race::OnceBox::new(),
                    phantom: std::marker::PhantomData,
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
        }
    }
}

impl<'a, T> Task<'a, T>
where
    T: Clone + Send + 'static,
{
    pub fn retrieve(&self) -> T {
        let v = self
            .result
            .get()
            .expect("value was empty - perhaps task has panicked");
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

#[pin_project::pin_project]
pub struct RequestHandle<'a, T>
where
    T: Clone + Send + 'static,
{
    #[pin]
    inner: RequestHandleInner<'a, T>,
}

#[pin_project::pin_project(project = RequestHandleInnerProj, project_replace = RequestHandleInnerProjReplace)]
enum RequestHandleInner<'a, T>
where
    T: Clone + Send + 'static,
{
    Pending(std::sync::Arc<Task<'a, T>>),
    Starting,
    Waiting {
        task: std::sync::Arc<Task<'a, T>>,
        notify: &'a tokio::sync::Notify,
        #[pin]
        wait: tokio::sync::futures::Notified<'a>,
    },
}

impl<'a, T> std::future::Future for RequestHandle<'a, T>
where
    T: Clone + Send + 'static,
{
    type Output = T;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut this = self.project();

        if let RequestHandleInnerProj::Waiting { task, wait, notify } = this.inner.as_mut().project() {
            return match wait.poll(cx) {
                std::task::Poll::Pending => std::task::Poll::Pending,
                std::task::Poll::Ready(_) => std::task::Poll::Ready(task.retrieve()),
            };
        }

        match this
            .inner
            .as_mut()
            .project_replace(RequestHandleInner::Starting)
        {
            RequestHandleInnerProjReplace::Pending(task) => {
                let wait = task.notify.notified();
                this.inner.set(RequestHandleInner::Waiting { task, wait, notify: &task.notify });
                match this.inner.project() {
                    RequestHandleInnerProj::Waiting { task, wait, notify: &task.notify } => match wait.poll(cx) {
                        std::task::Poll::Pending => std::task::Poll::Pending,
                        std::task::Poll::Ready(_) => std::task::Poll::Ready(task.retrieve()),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
        //    RequestHandleProj::Pending(task) => {
        //        if let Some(v) = task.result.get() {
        //            let value = v.lock();
        //            return std::task::Poll::Ready(value.clone());
        //        }
        //        let wait = task.notify.notified();
        //        match self.project_replace(RequestHandle::Waiting {
        //            task: task.clone(),
        //            wait,
        //        }) {
        //            RequestHandleProjOwn::Pending(_) => std::task::Poll::Pending,
        //            _ => unreachable!(),
        //        }
        //    }
        //    RequestHandleProj::Waiting { task, wait } => match wait.poll(cx) {
        //        std::task::Poll::Pending => std::task::Poll::Pending,
        //        std::task::Poll::Ready(_) => std::task::Poll::Ready(task.retrieve()),
        //    },
        //}

        //       let poll = if self.wait.is_none() {
        //           let n = self.task.notify.notified();
        //           let this = self.project_replace(RequestHandle {
        //               task: self.task.clone(),
        //               wait: Some(n),
        //           });
        //           let notified: std::pin::Pin<&mut tokio::sync::futures::Notified<'a>> =
        //               this.wait.unwrap();
        //           notified.poll(cx)
        //       } else {
        //           let this = self.project();
        //           let notified: std::pin::Pin<&mut tokio::sync::futures::Notified<'a>> =
        //               this.wait.unwrap();
        //           notified.poll(cx)
        //       };

        //       match notified.poll(cx) {
        //           std::task::Poll::Pending => std::task::Poll::Pending,
        //           std::task::Poll::Ready(_) => {
        //               let v = this
        //                   .task
        //                   .result
        //                   .get()
        //                   .expect("value was empty - perhaps task has panicked");
        //               let value = v.lock();
        //               std::task::Poll::Ready(value.clone())
        //           }
        //       }
    }
}

async fn ensure_completion<T>(task: std::sync::Arc<Task<'_, T>>, fut: FutureCapturingIntoMutex<T>)
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

async fn panic_protection<T>(task: std::sync::Arc<Task<'_, T>>, handle: tokio::task::JoinHandle<()>)
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
        let group = Singleflight::<()>::new();
        group.request("aa".to_string(), || async { panic!() }).await;
    }

    #[tokio::test]
    async fn collapsing() {
        let group = Singleflight::new();

        let (tx, rx) = tokio::sync::oneshot::channel();

        eprintln!("fut0");
        let fut0 = group.request("a".to_string(), || async move {
            rx.await.ok();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            42
        });
        eprintln!("fut1");
        let fut1 = group.request("a".to_string(), || async { 0 });
        eprintln!("fut2");
        let fut2 = group.request("a".to_string(), || async { 1 });

        eprintln!("fut3");
        let fut3 = group.request("b".to_string(), || async { 420 });

        let r2 = fut2.await;
        tx.send(()).unwrap();
        let (r0, r1, r3) = tokio::join!(fut0, fut1, fut3);
        assert_eq!(r0, 42);
        assert_eq!(r1, 42);
        assert_eq!(r2, 42);
        assert_eq!(r3, 420);

        let fut2 = group.request("a".to_string(), || async { 2 });
        assert_eq!(fut2.await, 1);
    }
}
