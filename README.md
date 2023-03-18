# GZY_ChatRoom
 这是一个用python编写的多人聊天室+文件服务器。
 
 This is an ultra-small multiplayer chat room + file server written in Python.
 
 本项目包含以下内容：
 
1. 一个超小型的python聊天服务器，部署方便，使用简单。
2. 一个UI界面设计得十分简陋但是能用的客户端，用于对接python服务器。
3. 一个迷你的python文件服务器，可以实现查看、上传和下载文件功能，自带哈希校验保证文件完整性。

## 项目目录
- [项目介绍](#项目介绍)
- [安装](#安装)
 - [源码安装](#源码安装)
 - [可执行文件安装](#可执行文件安装)
- [使用说明](#使用说明)
 - [聊天功能](#聊天功能)
 - [文件收发功能](#文件收发功能)
- [示例](#示例)
- [维护者](#维护者)
- [如何贡献](#如何贡献)
- [使用许可](#使用许可)

## 项目介绍
 本项目是使用python编写的聊天室，集成了文件服务器的功能，能够实现文件的上传和下载。
 
 项目优点：
 - 体积较小，占用资源少，非常适合轻量级设备部署。
 - 源码简单易懂，适合网络编程的学习。
 - 虽然UI界面简陋，但可以实现关键的功能，足够使用。
 - 源码依赖的东西较少，大部分网络操作使用python原生的socket库实现，部署时出现不兼容的情况几乎没有。
 
 项目缺点：
 - 功能太少，而且有些功能不完善，有些代码没有经过优化，存在隐藏的bug，请谨慎使用。（作者水平不足，但已经尽力增加完整的异常处理机制，按手册正常使用不会出现问题。）
 - 界面简陋，操作较为复杂。（需要记忆简单的中文指令）
 - 不支持内网穿透，推荐在拥有公网IP的服务器上部署，或采用[coplar](https://www.cpolar.com/)进行内网穿透。（也可采用其他方法进行内网穿透）
 
## 安装
 可以采用如下两种方案部署服务器：源码安装和可执行文件安装。
### 源码安装
1.克隆项目到本地：

```sh
$ git clone https://github.com/JiaXinSugar-114514/GZY_CahtRoom
# Prints out the standard-readme spec
```

 
 
