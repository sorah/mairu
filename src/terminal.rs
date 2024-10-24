use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

//#[macro_export]
//macro_rules! puts {
//    ($($arg:stmt)+) => {{
//        $crate::terminal::send(&indoc::formatdoc! {$($arg)*}).await;
//    }}
//}
//pub(crate) use puts;

struct Message(String);

struct OutputTask {
    tx: tokio::sync::mpsc::Sender<Message>,
    is_terminal: bool,
}

static TASK: tokio::sync::OnceCell<OutputTask> = tokio::sync::OnceCell::const_new();

pub async fn send(m: &str) {
    let task = TASK.get_or_init(start).await;
    let s = if m.ends_with("\n") {
        m.to_owned()
    } else if m.ends_with("\0") {
        m.strip_suffix("\0").unwrap_or(m).to_owned()
    } else {
        format!("{m}\n")
    };
    match task.tx.send(Message(s)).await {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to send to terminal: {e}; {}", m);
        }
    }
}

pub async fn is_terminal() -> bool {
    let task = TASK.get_or_init(start).await;
    task.is_terminal
}

async fn start() -> OutputTask {
    let output = output();
    let is_terminal = output.is_terminal();
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    tokio::spawn(task(output, rx));
    OutputTask { tx, is_terminal }
}

async fn task(mut output: Output, mut rx: tokio::sync::mpsc::Receiver<Message>) {
    while let Some(m) = rx.recv().await {
        match write(&mut output, m.0.as_bytes()).await {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to write to terminal: {e}; {}", m.0);
            }
        }
    }
}

async fn write(output: &mut Output, s: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    output.write_all(s).await?;
    output.flush().await?;
    Ok(())
}

#[pin_project::pin_project(project = OutputProj)]
#[derive(Debug)]
enum Output {
    File(#[pin] tokio::fs::File),
    Stderr(#[pin] tokio::io::Stderr),
}

fn output() -> Output {
    let fd = std::fs::OpenOptions::new()
        .append(true)
        .open("/dev/tty")
        .ok()
        .map(tokio::fs::File::from_std);
    match fd {
        Some(file) => Output::File(file),
        None => Output::Stderr(tokio::io::stderr()),
    }
}

impl Output {
    fn is_terminal(&self) -> bool {
        matches!(self, Output::File(_))
    }
}

impl tokio::io::AsyncWrite for Output {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        match this {
            OutputProj::File(mut f) => Pin::new(&mut f).poll_write(cx, buf),
            OutputProj::Stderr(mut f) => Pin::new(&mut f).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.project();
        match this {
            OutputProj::File(mut f) => Pin::new(&mut f).poll_flush(cx),
            OutputProj::Stderr(mut f) => Pin::new(&mut f).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.project();
        match this {
            OutputProj::File(mut f) => Pin::new(&mut f).poll_shutdown(cx),
            OutputProj::Stderr(mut f) => Pin::new(&mut f).poll_shutdown(cx),
        }
    }
}
