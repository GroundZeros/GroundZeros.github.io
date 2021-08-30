---
title: Spring Security整合JWT令牌OAuth2.0 
author: 糖果炒蛋
tags: Spring Security OAuth JWT 认证 鉴权
---



最近有个商场项目，业务搭建的差不多了，需要一个鉴权授权框架，正好学习一下OAuth2.0，平时做项目接触搭Spring Security不算多，搭建起来配置文件有点多，记录一下搭建过程，尽量介绍每一步的目的。

## 授权服务器搭建

授权服务器搭主要通过继承AuthorizationServerConfigurerAdapter类来实现，该类中有三个configuration方法，分别对应：

- **ClientDetailsServiceConfigurer**用来配置客户端详情服务，客户端详情信息在这里初始化，一般通过数据库存储客户端id与密码，校验申请令牌的客户端是否合法，类似Spring Security的UserSetailService
- **AuthorizationServerEndpointsConfigurer**用来配置令牌（Token）的访问url和令牌服务（Token Service）如：JWT令牌
- **AuthorizationServerSecurityConfigurer**用来配置令牌端点的安全约束，类似Spring Security中的HttpSecurity

（创建的类要加上@Configuration、@EnableAuthorizationServer注解，注明认证服务，托管给Spring）

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationService extends AuthorizationServerConfigurerAdapter {
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        super.configure(security);
    }
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        super.configure(clients);
    }
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        super.configure(endpoints);
    }
```

### 客户端详情配置

ClientDetailsServiceConfigurer一般使用JDBC连接数据库，查找`oauth_client_details`表中的客户端信息，表名不可更改，相关建表语句以及字段解释网上很容易找到，不再赘述。

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationService extends AuthorizationServerConfigurerAdapter {
    //注入数据源
    @Autowired
    private DataSource dataSource;
    
    //客户端数据源配置
    @Bean
    public ClientDetailsService clientDetails() {
        return new JdbcClientDetailsService(dataSource);
    }
    /**
    * 客户端详情
    */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetails());
    }
```

首先配置ClientDetailsService客户端数据源，然后在ClientDetailsServiceConfigurer中把配置好的客户端客户端加入。

### 令牌访问端点配置

**AuthorizationServerEndpointsConfigurer**可以完成令牌服务以及令牌endpoint配置。主要通过以下属性决定支持的**授权类型**：

- authenticationManager：认证管理器，当你选择了资源所有者密码（password）授权类型的时候，请设置这个属性，注入一个AuthenticationManager对象。
- userDetailsService：如果你设置了这个属性，说明你有一个自己的UserDetailsService接口实现，或者你可以把这个东西设置到全局域上去（例如GlobalAuthenticationManagerConfiguration这个配置对象），当你设置了合格之后，那么“refresh_token”即刷新令牌授权类模型的流程中就会包含一个检查，用来确保这个账号是否仍然有效。
- authorizationCodeService：这个属性是用来设置授权码服务的（即AuthorizationCodeService的实例对象），主要用于”authorization_code“授权码类型模式。
- implicitGrantService：这个实行用于设置隐式授权模型，用来管理隐式授权模型的状态。
- tokenGranter：当你设置了这个东西（即实现TokenGranter接口），那么授权将会完全交由你来掌控，一般不适用。

**这一部分配置较为复杂，本文主要使用密码授权模式。**

#### UserDetailsService

首先要实现自定义UserDetailsService，实现对客户端以及用户的身份认证。

- 客户端认证可以注入上一步中ClientDetailsService，使用loadClientByClientId()方法实现。
- 用户认证通过Feign接口实现。

```java
/**
  * 自定义授权认证
  *
  * @Author: GroundZeros
  * @date: 21/8/30 14:30
  */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private UserFeign userFeign;

    /**
     * 自定义认证授权
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //=================================客户端信息认证 start========================================
        //取出Authentication，如果为空，说明未认证
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //统一采用httpBasic认证，httpBasic中存储了client_id和client_secret
        if (authentication == null) {
            //根据客户端id查询数据库,username此时代表客户端id
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(username);
            if (clientDetails != null) {
                //密钥
                String clientSecret = clientDetails.getClientSecret();
                return new User(username,//客户端id
                                clientSecret,//客户端密码
                                AuthorityUtils.commaSeparatedStringToAuthorityList(""));//分配客户端权限
            }
        }

        //=================================客户端信息认证 end==========================================

        //=================================用户账号密码信息认证 start==========================================
        if (StringUtils.isEmpty(username)) {
            return null;
        }
        Result<MallUser> userResult = userFeign.findById(username);
        if (userResult == null || userResult.getData() == null) {
            return null;
        }
        //用户密码
        String passwordBCry = userResult.getData().getPasswordBCry();
        //设置权限信息
        String permissions = "";

        UserJwt userJwt = new UserJwt(username, passwordBCry, AuthorityUtils.commaSeparatedStringToAuthorityList(permissions));
        //=================================用户账号密码信息认证 end==========================================

        return userJwt;
    }
}
```

#### AuthenticationManager

配置authenticationManager要实现WebSecurityConfigurerAdapter，新建类WebSecurityConfig

```java
@Configuration
@EnableWebSecurity
@Order(-1)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 密码加密
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 授权管理认证对象
     */
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception{
        AuthenticationManager authenticationManager = super.authenticationManagerBean();
        return authenticationManager;
    }

    /**
     * 安全拦截
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .httpBasic()        //启用Http基本身份验证
            .and()
            .formLogin()       //启用表单身份验证
            .and()
            .authorizeRequests()    //限制基于Request请求访问
            .anyRequest()
            .authenticated();       //其他请求都需要经过验证
    }
}
```

注意：授权认证管理对象重写的是authenticationManager**Bean**()，重写authenticationManager会造成OverFlow

#### JwtAccessTokenConverter与TokenStore

默认情况下,资源服务器解析后的token不会包含之前颁发时额外携带的字段信息得重写UserAuthenticationConverter自定义解析实现,将token转化为用户信息

```java
/**
  * 令牌信息转换
  *
  * @Author: GroundZeros
  * @date: 21/8/30 14:26
  */
@Configuration
public class CustomUserAuthenticationConverter extends DefaultUserAuthenticationConverter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        LinkedHashMap response = new LinkedHashMap();
        String name = authentication.getName();
        response.put("username", name);

        Object principal = authentication.getPrincipal();
        UserJwt userJwt;
        if (principal instanceof UserJwt) {
            userJwt = (UserJwt) principal;
        } else {
            //手动调用userdetailService获取用户信息，得到 UserJwt
            UserDetails userDetails = userDetailsService.loadUserByUsername(name);
            userJwt = (UserJwt) userDetails;
        }
        response.put("name", userJwt.getName());
        response.put("id", userJwt.getId());
        if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            response.put("authorities", AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
        }
        return response;
    }
}
```

自定义的UserAuthenticationConverter，继承自DefaultUserAuthenticationConverter，重写了**convertUserAuthentication**方法。默认该方法是获取authentication中的**username**和**权限信息**。而我们重写的方法里面还获取了authentication中的**principal**，判断是不是我们自定义的**UserJwt**，不是的话就调用**userDetailsService.loadUserByUsername**去获取，然后将**userJwt**中的**name**和**id**获取出来，添加到返回的map中。

将密钥文件与自定义的令牌转换器配置在TokenConfig的JwtAccessTokenConverter中，托管给Spring

```java
/**
  * 令牌配置
  *
  * @Author: GroundZeros
  * @date: 21/8/30 14:21
  */
@Configuration
public class TokenConfig {

    @Autowired
    @Qualifier("keyProp")
    private KeyProperties keyProperties;

    //读取密钥配置
    @Bean("keyProp")
    public KeyProperties keyProperties() {
        return new KeyProperties();
    }

    /**
     * JWT令牌转换器
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter(CustomUserAuthenticationConverter customUserAuthenticationConverter) {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyPair keyPair = new KeyStoreKeyFactory(
            keyProperties.getKeyStore().getLocation(),                    //密钥路径
            keyProperties.getKeyStore().getSecret().toCharArray())        //密钥访问密码
            .getKeyPair(
            keyProperties.getKeyStore().getAlias(),                 //密钥别名
            keyProperties.getKeyStore().getPassword().toCharArray());//密钥库访问密码
        converter.setKeyPair(keyPair);

        //配置自定义的CustomUserAuthenticationConverter
        DefaultAccessTokenConverter accessTokenConverter = (DefaultAccessTokenConverter) converter.getAccessTokenConverter();
        accessTokenConverter.setUserTokenConverter(customUserAuthenticationConverter);
        return converter;
    }

    /**
     * 令牌存储
     * @param jwtAccessTokenConverter
     * @return
     */
    @Bean
    public TokenStore tokenStore(JwtAccessTokenConverter jwtAccessTokenConverter) {
        return new JwtTokenStore(jwtAccessTokenConverter);
    }

}
```

其中JWT令牌转换器的密钥文件路径及密码配置在yml

```yml
encrypt:
  key-store:
    location: classpath:/farm_mall.jks
    secret: 密钥库密码
    alias: 密钥库别名
    password: 密钥访问密码
```



至此，令牌访问端点所需配置都已准备额完毕，在AuthorizationService中注入配置如下，（为了保证代码简洁，不包含其他配置属性、方法）

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationService extends AuthorizationServerConfigurerAdapter {
    //TokenConfig中的jwt令牌转换器
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    //SpringSecurity 用户自定义授权认证类
    @Autowired
    private UserDetailsService userDetailsService;
    //令牌存储策略
    @Autowired
    private TokenStore tokenStore;
    //授权认证管理器
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 授权服务器端点配置
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)  //认证管理器
            .tokenStore(tokenStore)                         //JWT令牌存储，(JWT不需要令牌服务)
            .userDetailsService(userDetailsService)         //用户信息Service
            .accessTokenConverter(jwtAccessTokenConverter); //JWT令牌转换器
    }

}
```

### 令牌端点安全约束

这一部分较为简单，直接上代码

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationService extends AuthorizationServerConfigurerAdapter {
    /**
     * 授权服务器安全配置
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.allowFormAuthenticationForClients()             //允许表单认证
            .passwordEncoder(new BCryptPasswordEncoder())    //密钥加密方法
            .tokenKeyAccess("permitAll()")                    //oauth/token_key公开
            .checkTokenAccess("isAuthenticated()");           //oauth/check_token只允许认证用户访问
    }
}
```

### 令牌获取测试（密码模式）

最终项目结构

![image-20210830201545167](https://cdn.jsdelivr.net/gh/GroundZeros/ImageHost@main/images/20210830201554.png)

启动项目使用POST请求访问/oauth/token，选择密码模式，填入用户账号密码，在Authorization中使用Basic Auth填入表`oauth_client_details`的客户端账号密码。

![image-20210830201828073](https://cdn.jsdelivr.net/gh/GroundZeros/ImageHost@main/images/20210830201828.png)

![image-20210830201857960](https://cdn.jsdelivr.net/gh/GroundZeros/ImageHost@main/images/20210830201857.png)

获得JWT令牌如下

![image-20210830202127186](https://cdn.jsdelivr.net/gh/GroundZeros/ImageHost@main/images/20210830202127.png)

令牌获取成功

