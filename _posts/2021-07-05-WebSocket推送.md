---
title: WebSocket消息推送
tag: socket
author: 糖果炒蛋
---

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