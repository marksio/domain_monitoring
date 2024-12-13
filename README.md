# domain_monitoring
Domain Monitoring using Python on 备案域名 ICP License Checking.

Thank You to https://github.com/HG-ha/ICP_Query and OpenAI ChatGPT
ICP备案查询: https://github.com/HG-ha/ICP_Query

# 拉取镜像
docker pull yiminger/ymicp:latest
# 运行并转发容器16181端口到本地所有地址
docker run -d -p 16181:16181 yiminger/ymicp:latest

http://0.0.0.0:16181/query/{type}?search={name}
curl http://127.0.0.1:16181/query/web?search=baidu.com

ICP Platform
https://beian.miit.gov.cn/#/Integrated/index
https://www.beian88.com/
https://www.beianx.cn/search/
http://www.jucha.com/beian/
https://seo.chinaz.com/
https://beian.tianyancha.com/
https://www.beiancha.com/domain/
https://icplishi.com/
https://www.icplist.com/icp/info/
https://icp.aizhan.com/
