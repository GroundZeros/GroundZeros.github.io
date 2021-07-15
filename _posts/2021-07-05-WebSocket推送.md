---

title: WebSocket消息推送
tag: socket
author: 糖果炒蛋
---

WebSocket是 HTML5 开始提供的一种在单个 TCP 连接上进行全双工通讯的协议。

以前的推送技术使用 Ajax 轮询，浏览器需要不断地向服务器发送http请求来获取最新的数据，浪费很多的带宽等资源。

使用webSocket通讯，客户端和服务端只需要一次握手建立连接，就可以互相发送消息，进行数据传输，更实时地进行通讯。

浏览器先向服务器发送个url以`ws://`开头的http的GET请求，响应状态码101表示Switching Protocols切换协议，

服务器根据请求头中Upgrade:websocket把客户端的请求切换到对应的协议，即websocket协议。

![img](https://cdn.jsdelivr.net/gh/GroundZeros/ImageHost@main/images/20210715164722.png)

![img](https://cdn.jsdelivr.net/gh/GroundZeros/ImageHost@main/images/20210715164735.png)

响应头消息中包含Upgrade:websocket，表示它切换到的协议，即websocket协议。

![img](https://cdn.jsdelivr.net/gh/GroundZeros/ImageHost@main/images/20210715164800.png)

响应101，握手成功，http协议切换成websocket协议了，连接建立成功，浏览器和服务器可以随时主动发送消息给对方了，并且这个连接一直持续到客户端或服务器一方主动关闭连接。

![img](https://cdn.jsdelivr.net/gh/GroundZeros/ImageHost@main/images/20210715163434.png)

WebSocket抽象类，继承后只重写geturi()方法。

```java
public abstract class AbstractWebSocket implements IWebSocket{

    protected abstract String getUri();

    @OnOpen
    @Override
    public void onOpen(Session session) {
        WebSocketManager.getInstance().addSession(getUri(),session);
    }

    @OnClose
    @Override
    public void onClose(Session session) {
        WebSocketManager.getInstance().removeSession(getUri(),session);
    }

    @OnMessage
    @Override
    public void onMessage(String message, Session session) {
       /*广播模式，不单独推送*/
    }

    @OnError
    @Override
    public void onError(Session session, Throwable error) {
        WebSocketManager.getInstance().removeSession(getUri(),session);
        log.error("websocket error uri:{}，{}", getUri(),error.getMessage());
    }


}
```

WebSocket的告警推送实现类

```java
@ServerEndpoint(value = FaceUriConstant.URI_WEBSOCKET_TRACKPEOPLEALARMCENTER)
@Component
public class TrackPeopleAlarmCenterWebSocket extends AbstractWebSocket {
    @Override
    protected String getUri() {
        return FaceUriConstant.URI_WEBSOCKET_TRACKPEOPLEALARMCENTER;
    }
}
```

使用@ServerEndpoint表明服务端监听地址



OnOpen、OnClose获取Session放入或删除WebSocketManager的SessionMap，用于后续sendAllMessage发送消息。

WebSocketManager是统一管理WebSocket的管理类（饿汉单例模式），其getInstance()方法可以用于获取该对象，遍历Session发送信息。

```java
public class WebSocketManager {

    private static ConcurrentHashMap<String,Map<String,Session>> sessionMap = new ConcurrentHashMap<>();

    private static WebSocketManager webSocketManager = new WebSocketManager();
    private WebSocketManager(){}

    public static WebSocketManager getInstance(){
        return webSocketManager;
    }
    
    public void sendAllMessage(String key,String msg){
        Map<String,Session>  map = sessionMap.get(key);
        if(map == null){
            sessionMap.putIfAbsent(key,new HashMap<>(16));
            return;
        }
        log.info("uri：{}，online client count {}",key, sessionMap.get(key).size());
        Set<Map.Entry<String, Session>> entries = sessionMap.get(key).entrySet();
        for (Map.Entry<String, Session> entry : entries) {
            String cid = entry.getKey();
            Session session = entry.getValue();
            try {
                boolean sessionOpen = session.isOpen();
                if (sessionOpen) {
                    session.getBasicRemote().sendText(msg);
                } else {
                    log.info("sid {} is closed", cid);
                    removeSession(key,session);
                }
            }catch (Exception e){
                log.error("send websocket message error，uri：{}，sid：{}",key,e);
            }
        }
    }
```

消息推送实现类的推送方法中，封装好推送信息msg，只需要调用

```java
WebSocketManager.getInstance().sendAllMessage(uri, JsonUtil.toJsonString(msg));
```

实现消息推送。

参考链接：<https://www.cnblogs.com/liuyong1993/p/10718961.html>
