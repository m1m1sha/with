use std::{
    io::{Error, ErrorKind, Result},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread::{self, Thread},
};

use parking_lot::Mutex;

#[derive(Clone)]
pub struct Stoper {
    watch: Arc<Watch>,
}

impl Stoper {
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            watch: Arc::new(Watch::new(f)),
        }
    }

    pub fn add_listener<F>(&self, name: String, f: F) -> Result<Worker>
    where
        F: FnOnce() + Send + 'static,
    {
        self.watch.add_listener(name, f)
    }

    pub fn stop(&self) {
        self.watch.stop("");
    }

    pub fn wait(&self) {
        self.watch.wait();
    }

    pub fn is_stop(&self) -> bool {
        self.watch.state.load(Ordering::Acquire)
    }
}

pub struct Watch {
    listeners: Mutex<(bool, Vec<(String, Box<dyn FnOnce() + Send>)>)>,
    park_threads: Mutex<Vec<Thread>>,
    worker_num: AtomicUsize,
    state: AtomicBool,
    stop_call: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Watch {
    fn new<F>(f: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            listeners: Mutex::new((false, Vec::with_capacity(32))),
            park_threads: Mutex::new(Vec::with_capacity(4)),
            worker_num: AtomicUsize::new(0),
            state: AtomicBool::new(false),
            stop_call: Mutex::new(Some(Box::new(f))),
        }
    }

    fn add_listener<F>(self: &Arc<Self>, name: String, f: F) -> Result<Worker>
    where
        F: FnOnce() + Send + 'static,
    {
        if name.is_empty() {
            return Err(Error::new(ErrorKind::Other, "任务名称不能为空"));
        }

        let mut guard = self.listeners.lock();

        if guard.0 {
            return Err(Error::new(ErrorKind::Other, "任务已经停止"));
        }

        for (n, _) in &guard.1 {
            if &name == n {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("该名称已经存在 {:?}", name),
                ));
            }
        }
        guard.1.push((name.clone(), Box::new(f)));
        Ok(Worker::new(name, self.clone()))
    }

    fn stop(&self, skip_name: &str) {
        self.state.store(true, Ordering::Release);
        let mut guard = self.listeners.lock();
        guard.0 = true;

        for (name, listener) in guard.1.drain(..) {
            if &name == skip_name {
                continue;
            }
            listener();
        }
    }

    fn wait(&self) {
        {
            let mut guard = self.park_threads.lock();
            guard.push(thread::current());
            drop(guard);
        }
        loop {
            if self.worker_num.load(Ordering::Acquire) == 0 {
                return;
            }
            thread::park()
        }
    }

    fn stop_call(&self) {
        if let Some(call) = self.stop_call.lock().take() {
            call();
        }
    }
}

pub struct Worker {
    name: String,
    watch: Arc<Watch>,
}

impl Worker {
    fn new(name: String, watch: Arc<Watch>) -> Self {
        let _ = watch.worker_num.fetch_add(1, Ordering::AcqRel);
        Self { name, watch }
    }

    fn release(&self) {
        let watch = &self.watch;
        let count = watch.worker_num.fetch_sub(1, Ordering::AcqRel);
        if count == 1 {
            for x in watch.park_threads.lock().drain(..) {
                x.unpark();
            }
            self.watch.stop_call();
        }
    }

    pub fn stop_all(self) {
        self.watch.stop(&self.name)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.release();
        tracing::info!("stop {}", self.name);
    }
}
