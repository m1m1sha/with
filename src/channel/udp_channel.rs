use std::collections::HashMap;
use std::net::UdpSocket as StdUdpSocket;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::Arc;
use std::{io, thread};

use mio::event::Source;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::channel::context::Context;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::notify::AcceptNotify;
use crate::channel::sender::AcceptSocketSender;
use crate::channel::{RouteKey, BUFFER_SIZE};
use utils::work::Stoper;

pub fn udp_listen<H>(
    stoper: Stoper,
    recv_handler: H,
    context: Context,
) -> io::Result<AcceptSocketSender<Option<Vec<UdpSocket>>>>
where
    H: RecvChannelHandler,
{
    main_udp_listen(stoper.clone(), recv_handler.clone(), context.clone())?;
    sub_udp_listen(stoper, recv_handler, context)
}

const NOTIFY: Token = Token(0);

fn sub_udp_listen<H>(
    stoper: Stoper,
    recv_handler: H,
    context: Context,
) -> io::Result<AcceptSocketSender<Option<Vec<UdpSocket>>>>
where
    H: RecvChannelHandler,
{
    let (udp_sender, udp_receiver) = sync_channel(64);
    let poll = Poll::new()?;
    let waker = AcceptNotify::new(Waker::new(poll.registry(), NOTIFY)?);
    let worker = {
        let waker = waker.clone();
        stoper.add_listener("sub_udp_listen".into(), move || {
            if let Err(e) = waker.stop() {
                tracing::error!("{:?}", e);
            }
        })?
    };
    let accept = AcceptSocketSender::new(waker.clone(), udp_sender);
    thread::Builder::new()
        .name("sub_udp读事件处理线程".into())
        .spawn(move || {
            if let Err(e) = sub_udp_listen0(poll, recv_handler, context, waker, udp_receiver) {
                tracing::error!("{:?}", e);
            }
            worker.stop_all();
        })?;
    Ok(accept)
}

fn sub_udp_listen0<H>(
    mut poll: Poll,
    mut recv_handler: H,
    context: Context,
    accept_notify: AcceptNotify,
    accept_receiver: Receiver<Option<Vec<UdpSocket>>>,
) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    let mut events = Events::with_capacity(1024);
    let mut buf = [0; BUFFER_SIZE];
    let mut read_map: HashMap<Token, UdpSocket> = HashMap::with_capacity(32);
    loop {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            match event.token() {
                NOTIFY => {
                    if accept_notify.is_stop() {
                        return Ok(());
                    }
                    if accept_notify.is_add_socket() {
                        while let Ok(option) = accept_receiver.try_recv() {
                            match option {
                                None => {
                                    tracing::info!("切换成锥形模式");
                                    for (_, mut udp_socket) in read_map.drain() {
                                        if let Err(e) = udp_socket.deregister(poll.registry()) {
                                            tracing::error!("{:?}", e);
                                        }
                                    }
                                }
                                Some(socket_list) => {
                                    tracing::info!(
                                        "切换成对称模式 监听端口数：{}",
                                        socket_list.len()
                                    );
                                    for (index, mut udp_socket) in
                                        socket_list.into_iter().enumerate()
                                    {
                                        let token = Token(index + context.channel_num());
                                        poll.registry().register(
                                            &mut udp_socket,
                                            token,
                                            Interest::READABLE,
                                        )?;
                                        read_map.insert(token, udp_socket);
                                    }
                                }
                            }
                        }
                    }
                }
                token => {
                    if let Some(udp_socket) = read_map.get(&token) {
                        loop {
                            match udp_socket.recv_from(&mut buf) {
                                Ok((len, addr)) => {
                                    recv_handler.handle(
                                        &mut buf[..len],
                                        RouteKey::new(false, token.0, addr),
                                        &context,
                                    );
                                }
                                Err(e) => {
                                    if e.kind() == io::ErrorKind::WouldBlock {
                                        break;
                                    }
                                    tracing::error!("{:?}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 阻塞监听
fn main_udp_listen<H>(stoper: Stoper, recv_handler: H, context: Context) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    let poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), NOTIFY)?);
    let _waker = waker.clone();
    let worker = stoper.add_listener("main_udp".into(), move || {
        if let Err(e) = waker.wake() {
            tracing::error!("{:?}", e);
        }
    })?;
    thread::Builder::new()
        .name("main_udp".into())
        .spawn(move || {
            if let Err(e) = main_udp_listen0(poll, recv_handler, context) {
                tracing::error!("{:?}", e);
            }
            drop(_waker);
            worker.stop_all();
        })?;
    Ok(())
}

pub fn main_udp_listen0<H>(mut poll: Poll, mut recv_handler: H, context: Context) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    let mut buf = [0; BUFFER_SIZE];
    let mut udps = Vec::with_capacity(context.main_udp_socket.len());

    for (index, udp) in context.main_udp_socket.iter().enumerate() {
        let udp_socket = udp.try_clone()?;
        udp_socket.set_nonblocking(true)?;
        let mut mio_udp = UdpSocket::from_std(udp_socket);
        poll.registry()
            .register(&mut mio_udp, Token(index + 1), Interest::READABLE)?;
        udps.push(mio_udp);
    }

    let mut events = Events::with_capacity(udps.len());
    loop {
        poll.poll(&mut events, None)?;
        for x in events.iter() {
            let index = match x.token() {
                NOTIFY => return Ok(()),
                Token(index) => index - 1,
            };
            loop {
                match udps[index].recv_from(&mut buf) {
                    Ok((len, addr)) => {
                        recv_handler.handle(
                            &mut buf[..len],
                            RouteKey::new(false, index, addr),
                            &context,
                        );
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            break;
                        }
                        tracing::error!("main_udp_listen_{}={:?}", index, e);
                    }
                }
            }
        }
    }
}
