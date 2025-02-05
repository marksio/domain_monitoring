# domain_monitoring
Domain Monitoring using Python on 备案域名 ICP License Checking.

"""
Thank You to https://github.com/HG-ha/ICP_Query and OpenAI ChatGPT
ICP备案查询: https://github.com/HG-ha/ICP_Query
Docker Hub: https://hub.docker.com/r/yiminger/ymicp/tags

# 拉取镜像
docker pull yiminger/ymicp:yolo8_latest
# 运行并转发容器16181端口到本地所有地址
docker run -d -p 16181:16181 yiminger/ymicp:yolo8_latest

http://0.0.0.0:16181/query/{type}?search={name}
curl http://127.0.0.1:16181/query/web?search=baidu.com

# Install all necessary Python Module or Package
pip install requests python-whois pymongo

# Will use cronjob in Linux to repeat (Every 6 Hours execute below script - sudo crontab -e)
0 */6 * * * /usr/bin/python3 /backup/domain_monitor.py >> /backup/domain_monitor_logfile.log 2>&1

# Access MongoDB on Docker
docker exec -it <MONGODB_DOCKER_ID> bash
mongo -u username -p password

"""

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
