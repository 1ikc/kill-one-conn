### koc (kill-one-conn)

**背景**

- 调试长连接程序，e.g. ⇒ WebSocket连接的断线重连。
- 关闭某个TCP连接，e.g. ⇒ 由于用户违规断线指定的WebSocket连接。
- 如果是在服务端控制，直接kill进程会导致所有连接失效，服务不可用，是不可取的。

针对以上场景，我们需要一种可以细粒度关闭TCP连接的工具。

**已有工具**

结合现有的tcpkill和killcx，发现使用起来不如意。

- tcpkill不能立即关闭连接，需要等待有新的数据传输后才进行连接关闭。
- killcx是perl脚本，安装起来相对繁琐。

因此有了造轮子的想法💡。

**特性**

- 支持立即/延时关闭连接
- 支持一定时间内拦截指定连接并自动退出程序
- 支持其他项目复用
- 下载即用
- 目前仅适用于IPv4

<br>

### 使用说明

> 需要保证系统已支持libpcap扩展，下文提供安装方式。
> 

- CLI
  <br>
  release下载最新二进制文件koc
  ```go
  ./koc
    -nic {nic} 
    -src_ip {src_ip} -dst_ip {dst_ip} 
    -src_port {src_port} -dst_port {dst_port}
    -delay {delay}
    -timeout {duration}
    -retry {retry}
  ```

  - nic：监听的网络接口卡。
  - src_ip：来源IP，使用点分十进制。
  - dst_ip：目的IP，使用点分十进制。
  - src_port：源端口。
  - dst_port：目的端口。
  - delay：延时关闭时间，默认0，单位ms。
  - timeout：持续拦截时间，默认0，单位ms。
  - retry：RST报文的重传机制，默认3。

- Module
  ```go
  import (
    koc "github.com/1ikc/kill-one-conn"
  )
  
  func killConn(nic string, options ...koc.Option) {
    // 构建拦截器
    t, _ = koc.Build(
      nic,
      options...,
    )
    // 启动拦截
    t.Intercept()
  }
  ```

<br>

### 运行截图
![运行kill-one-conn](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/937d6225-eea1-4e66-af3f-9d8537a3ac15/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20220215%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20220215T085504Z&X-Amz-Expires=86400&X-Amz-Signature=c581b7fcdae0d49e53a46bf3aa232394718127abd5b5eb80384302643c791e7a&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22&x-id=GetObject)

<br>

### 问题汇总

> 环境以CentOS为准
> 
- 工具提示 `error while loading shared libraries: libpcap.so.0.8: xxx`
    - 安装libpcap
        
        `yum install libpcap-devel`
        
    - 创建软连接
        
        `sudo ln -s /usr/lib64/libpcap.so /usr/lib64/libpcap.so.0.8`
        
- 交叉编译提示 `gopacket/pcap: undefined xxx`
    - gopacket使用了CGO，编译开启CGO_ENABLED。
    - 安装C交叉编译器
    - 指定C交叉编译器，交叉编译linux版本
    
    ⚠️未解决成功，macOS交叉编译还是失败，转到Linux系统编译。如有其他办法，望不吝赐教。
    
<br>

### 原理

伪造RST包，包的序号利用challenge-ack机制获得。

**challenge-ack机制**

向ESTABLISHED状态的连接，发送SYN报文。会接收到challenge-ack报文，获取报文中的ack伪造RST报文并发给其中一方。

**注意**

如果在生产环境抓包发现ESTABLISHED状态的连接有SYN报文到达，需要留意是否正遭受RST攻击。

<br>

### tcpkill抓包实践

**抓包流程**

- 使用 `nc` 工具建立一条TCP长连接。
    - `nc -l 40033` 启动服务端
    - `nc 127.0.0.1 40033 -p 40022` 启动客户端
    - `tcpdump` 抓包结果 ⇒ TCP的三次握手完成
        
        ![tcpdump抓包结果1](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/966bacad-f291-4ad8-8358-7f53406d022c/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20220215%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20220215T065119Z&X-Amz-Expires=86400&X-Amz-Signature=8dc07de7ec696b5cc6b98c6775f89a3a12673f843aaba5b160efdde3b3cfa692&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22&x-id=GetObject)
        
- 使用 `tcpkill` 工具关闭一条活跃的TCP连接。
    - `tcpkill -i lo -3 port 40033` ，同时在nc服务端发送数据，运行结果 ⇒
        
        ![tcpkill抓包结果](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/fc40dfbf-f190-4952-ab4c-4bc3d28bf66c/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20220215%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20220215T065105Z&X-Amz-Expires=86400&X-Amz-Signature=a1f7fdd0da11abf49cea02ae76d154b84404a2387bc05d55a0a7dba015ed190e&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22&x-id=GetObject)
        
    - tcpdump抓包结果 ⇒ 伪造RST包关闭活跃连接
        
        ![tcpdump抓包结果1](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/296041dc-7a9f-4b86-bf34-02a2a841e5a5/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20220215%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20220215T065047Z&X-Amz-Expires=86400&X-Amz-Signature=824a69fb0967125096eaa640fdfade773836996b53855658d9e4cd3ecb3fca99&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22&x-id=GetObject)
        

**结论分析**

tcpkill执行后不是立即关闭连接，而是先监听40033端口的数据传输，当监听到有数据传输时，再伪造RST包进行连接的关闭。同时tcpkill关闭连接后不会自动退出程序。

<br>

### 引用

- 小林coding的图解网络系列-TCP篇某小节
- [tcpkill](https://www.jianshu.com/p/c8423cbe3e36)
- [CGO交叉编译](https://bansheelw.github.io/2019/12/18/macOS%E4%B8%8Bgolang%20%E4%BA%A4%E5%8F%89%E7%BC%96%E8%AF%91%E5%A4%B1%E8%B4%A5%E5%B0%8F%E8%AE%B0/)
