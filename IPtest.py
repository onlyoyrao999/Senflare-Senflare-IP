"""
Cloudflare优选IP采集器 v2.3.0
===============================================

一个高效、智能的Cloudflare优选IP采集和检测工具，专为网络优化而设计。

🎯 核心功能
-----------
• IP采集：多API源并发采集，获取大量候选IP地址
• 智能筛选：TCP连接测试快速剔除不可用IP
• 性能测试：TCP Ping延迟测试 + HTTP带宽测试
• 地区识别：自动识别IP地理位置，支持缓存机制
• 智能排序：综合延迟、带宽、稳定性进行评分排名
• 多格式输出：生成基础版和高级版IP列表文件

⚡ 技术特性
-----------
• 智能缓存：TTL机制减少重复API调用，提升效率
• 高并发处理：多线程并发检测，大幅提升速度
• 容错机制：完善的异常处理和重试策略
• 详细日志：完整的操作日志记录，支持文件输出
• 资源优化：自动缓存管理，防止内存溢出
• CI优化：针对GitHub Actions等CI环境特别优化
• 多端口支持：可配置测试端口，适应不同需求
• 评分系统：综合性能指标，智能排名推荐

📊 输出文件
-----------
• IPlist.txt - 基础版IP列表（快速筛选结果）
• Senflare.txt - 基础版格式化IP列表（按地区分组）
• IPlist-Pro.txt - 高级版IP列表（性能测试结果）
• Senflare-Pro.txt - 高级版格式化IP列表（按地区分组）
• Ranking.txt - 详细排名信息（延迟、带宽、评分）
• Cache.json - 地区信息缓存文件
• IPtest.log - 详细运行日志

🔧 配置说明
-----------
• 支持自定义测试端口、超时时间、并发数等参数
• 可开启/关闭高级模式（带宽测试、综合评分）
• 支持延迟排名筛选（取前N%的IP进行深度测试）
• 智能缓存管理，支持TTL和大小限制

作者：Senflare
版本：v2.3.0
更新：2025年10月25日
"""

# ===== 标准库导入 =====
# 正则表达式、文件操作、时间处理
import re
import os
import time
import socket
import json
import ipaddress
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ===== 第三方库导入 =====
# HTTP请求库和SSL警告处理
import requests
from urllib3.exceptions import InsecureRequestWarning

# ===== 配置和初始化 =====

# 禁用SSL证书警告，避免HTTPS请求时的警告信息
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# 配置日志系统 - 同时输出到文件和控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('IPtest.log', encoding='utf-8'),  # 文件日志
        logging.StreamHandler()  # 控制台日志
    ]
)
logger = logging.getLogger(__name__)

# ===== 核心配置 =====
# 程序运行的核心参数配置，可根据需要调整
CONFIG = {
    # 📥 IP来源配置 - 只解析这三个优选域名（用户定版，就留这三个地址）
    # 这三个域名是地域解析：权威按地区/运营商分线路返回不同 IP，
    # 靠 DoH + ECS 地域扫描（ecs_subnets.txt）把各线路的 IP 全量解出后取并集。
    "domains": [
        'lax.xxxxxxxx.nyc.mn',
        'saas.sin.fan',
        'cloudflare-ip.mofashi.ltd',
        'nrt.xxxxxxxx.nyc.mn',
    ],

    # 🔍 网络测试配置
    # HTTPS标准端口: 443
    # Cloudflare专用端口: 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8443, 8444
    "test_ports": [443],                    # TCP连接测试端口（可自定义多个端口，如[443, 2052, 2053]）
    "timeout": 15,                          # IP采集超时时间（秒）
    "api_timeout": 5,                       # API查询超时时间（秒）
    "query_interval": 0.2,                 # API查询间隔时间（秒）
    
    # ⚡ 并发处理配置（GitHub Actions环境优化）
    "max_workers": 15,                      # 最大并发线程数
    "batch_size": 10,                       # 批量处理IP数量
    "cache_ttl_hours": 168,                 # 缓存有效期（7天）
    
    # 🚀 高级功能配置
    "advanced_mode": True,                  # 高级模式开关（True=开启，False=关闭）
    "bandwidth_test_count": 3,              # 带宽测试次数
    "bandwidth_test_size_mb": 10,             # 带宽测试文件大小（MB）
    "latency_filter_percentage": 30,        # 延迟排名前百分比（取前30%的IP）
}

# ===== 国家/地区映射表 =====
# 将ISO国家代码映射为中文名称，支持全球主要国家和地区
COUNTRY_MAPPING = {
    # 统一添加常见国家和地区
    # 🌎 北美地区
    'US': '美国', 'CA': '加拿大', 'MX': '墨西哥', 'CR': '哥斯达黎加', 'GT': '危地马拉', 'HN': '洪都拉斯',
    'NI': '尼加拉瓜', 'PA': '巴拿马', 'CU': '古巴', 'JM': '牙买加', 'TT': '特立尼达和多巴哥',
    'BZ': '伯利兹', 'SV': '萨尔瓦多', 'DO': '多米尼加', 'HT': '海地',
    # 🌎 南美地区
    'BR': '巴西', 'AR': '阿根廷', 'CL': '智利', 'CO': '哥伦比亚', 'PE': '秘鲁', 'VE': '委内瑞拉',
    'UY': '乌拉圭', 'PY': '巴拉圭', 'BO': '玻利维亚', 'EC': '厄瓜多尔', 'GY': '圭亚那',
    'SR': '苏里南', 'FK': '福克兰群岛',
    # 🌍 欧洲地区
    'UK': '英国', 'GB': '英国', 'FR': '法国', 'DE': '德国', 'IT': '意大利', 'ES': '西班牙', 'NL': '荷兰',
    'RU': '俄罗斯', 'SE': '瑞典', 'CH': '瑞士', 'BE': '比利时', 'AT': '奥地利', 'IS': '冰岛',
    'PL': '波兰', 'DK': '丹麦', 'NO': '挪威', 'FI': '芬兰', 'PT': '葡萄牙', 'IE': '爱尔兰',
    'UA': '乌克兰', 'CZ': '捷克', 'GR': '希腊', 'HU': '匈牙利', 'RO': '罗马尼亚', 'TR': '土耳其',
    'BG': '保加利亚', 'LT': '立陶宛', 'LV': '拉脱维亚', 'EE': '爱沙尼亚', 'BY': '白俄罗斯',
    'LU': '卢森堡', 'LUX': '卢森堡', 'SI': '斯洛文尼亚', 'SK': '斯洛伐克', 'MT': '马耳他',
    'HR': '克罗地亚', 'RS': '塞尔维亚', 'BA': '波黑', 'ME': '黑山', 'MK': '北马其顿',
    'AL': '阿尔巴尼亚', 'XK': '科索沃', 'MD': '摩尔多瓦', 'GE': '格鲁吉亚', 'AM': '亚美尼亚',
    'AZ': '阿塞拜疆', 'CY': '塞浦路斯', 'MC': '摩纳哥', 'SM': '圣马力诺', 'VA': '梵蒂冈',
    'AD': '安道尔', 'LI': '列支敦士登',
    # 🌏 亚洲地区
    'CN': '中国', 'HK': '中国香港', 'TW': '中国台湾', 'MO': '中国澳门', 'JP': '日本', 'KR': '韩国',
    'SG': '新加坡', 'SGP': '新加坡', 'IN': '印度', 'ID': '印度尼西亚', 'MY': '马来西亚', 'MYS': '马来西亚',
    'TH': '泰国', 'PH': '菲律宾', 'VN': '越南', 'PK': '巴基斯坦', 'BD': '孟加拉', 'KZ': '哈萨克斯坦',
    'IL': '以色列', 'ISR': '以色列', 'SA': '沙特阿拉伯', 'SAU': '沙特阿拉伯', 'AE': '阿联酋', 
    'QAT': '卡塔尔', 'OMN': '阿曼', 'KW': '科威特', 'BH': '巴林', 'IQ': '伊拉克', 'IR': '伊朗',
    'AF': '阿富汗', 'UZ': '乌兹别克斯坦', 'KG': '吉尔吉斯斯坦', 'TJ': '塔吉克斯坦', 'TM': '土库曼斯坦',
    'MN': '蒙古', 'NP': '尼泊尔', 'BT': '不丹', 'LK': '斯里兰卡', 'MV': '马尔代夫',
    'MM': '缅甸', 'LA': '老挝', 'KH': '柬埔寨', 'BN': '文莱', 'TL': '东帝汶',
    'LK': '斯里兰卡', 'MV': '马尔代夫', 'NP': '尼泊尔', 'BT': '不丹',
    # 🌊 大洋洲地区
    'AU': '澳大利亚', 'NZ': '新西兰', 'FJ': '斐济', 'PG': '巴布亚新几内亚', 'NC': '新喀里多尼亚',
    'VU': '瓦努阿图', 'SB': '所罗门群岛', 'TO': '汤加', 'WS': '萨摩亚', 'KI': '基里巴斯',
    'TV': '图瓦卢', 'NR': '瑙鲁', 'PW': '帕劳', 'FM': '密克罗尼西亚', 'MH': '马绍尔群岛',
    # 🌍 非洲地区
    'ZA': '南非', 'EG': '埃及', 'NG': '尼日利亚', 'KE': '肯尼亚', 'ET': '埃塞俄比亚',
    'GH': '加纳', 'TZ': '坦桑尼亚', 'UG': '乌干达', 'DZ': '阿尔及利亚', 'MA': '摩洛哥',
    'TN': '突尼斯', 'LY': '利比亚', 'SD': '苏丹', 'SS': '南苏丹', 'ER': '厄立特里亚',
    'DJ': '吉布提', 'SO': '索马里', 'ET': '埃塞俄比亚', 'KE': '肯尼亚', 'TZ': '坦桑尼亚',
    'UG': '乌干达', 'RW': '卢旺达', 'BI': '布隆迪', 'MW': '马拉维', 'ZM': '赞比亚',
    'ZW': '津巴布韦', 'BW': '博茨瓦纳', 'NA': '纳米比亚', 'SZ': '斯威士兰', 'LS': '莱索托',
    'MZ': '莫桑比克', 'MG': '马达加斯加', 'MU': '毛里求斯', 'SC': '塞舌尔', 'KM': '科摩罗',
    'CV': '佛得角', 'ST': '圣多美和普林西比', 'GW': '几内亚比绍', 'GN': '几内亚', 'SL': '塞拉利昂',
    'LR': '利比里亚', 'CI': '科特迪瓦', 'GH': '加纳', 'TG': '多哥', 'BJ': '贝宁',
    'NE': '尼日尔', 'BF': '布基纳法索', 'ML': '马里', 'SN': '塞内加尔', 'GM': '冈比亚',
    'GN': '几内亚', 'GW': '几内亚比绍', 'ST': '圣多美和普林西比', 'CV': '佛得角',
    # ❓ 其他/未知
    'Unknown': '未知'
}

# ===== 全局变量 =====
# 地区信息缓存，用于存储IP地理位置查询结果
region_cache = {}


# ===== 固定节点名（400 条） =====
# 节点显示名固定使用这 400 条爱国爱党爱人民宣传语录（用户亲发原文：前 200 条 2026-11-24 定版、后 200 条同日续补），顺序写死；
# 同一份名单另存仓库根目录 node_names.txt（一行一条）：程序优先按该文件的顺序排列，内置名单只作兜底。
# 第 N 个 IP 永远配第 N 条，以后更新只换 IP、文字不动。
# 当前 IP 上限 100 个，只用到前 100 条；后 300 条是备份，以后放开上限直接续用。
# 同一个 IP 在基础版和高级版中使用同一条（按基础版顺序分配）。
FIXED_NODE_NAMES = [
    "守护红色江山，不负先辈牺牲。",
    "勇担复兴重任，书写青春答卷。",
    "党心连着民心，家国一脉同心。",
    "耕耘民生福祉，筑梦华夏山河。",
    "胸怀千秋伟业，心系亿万人民。",
    "红心永向党旗，实干报效祖国。",
    "牢记初心使命，厚植为民情怀。",
    "紧跟党的步伐，共筑复兴伟业。",
    "江山属于人民，初心始终如一。",
    "赓续红色血脉，勇担时代重任。",
    "常怀报国之志，永葆赤子之心。",
    "党旗引领航向，奋斗点亮中华。",
    "坚守为民初心，矢志对党忠诚。",
    "传承红色基因，争做时代新人。",
    "听党感恩奋进，同心建设家园。",
    "心系万家冷暖，情牵百姓安康。",
    "聚力强国建设，奔赴民族复兴。",
    "笃行实干担当，不负人民重托。",
    "礼赞锦绣山河，致敬伟大人民。",
    "信仰照亮前路，奋斗成就梦想。",
    "厚植家国情怀，砥砺强国之行。",
    "党恩润泽万家，同心逐梦前行。",
    "立足平凡岗位，奉献家国人民。",
    "高举伟大旗帜，奋进崭新征程。",
    "守望万里河山，守护一方百姓。",
    "青春向党而立，强国有我担当。",
    "铭记百年征程，坚守为民初心。",
    "凝聚民心力量，共绘盛世宏图。",
    "笃行报国初心，勇扛时代使命。",
    "红心扎根故土，热忱服务人民。",
    "坚守红色信仰，弘扬爱国正气。",
    "发展依靠人民，成果惠及人民。",
    "山河盛世如画，党心民心相通。",
    "矢志紧跟党走，同心振兴中华。",
    "高扬时代旋律，奋进伟大新程。",
    "以小我之微光，耀大国之荣光。",
    "初心扎根基层，真情温暖民心。",
    "红旗迎风招展，华夏阔步向前。",
    "常怀感恩之心，力行报国之举。",
    "弘扬爱国精神，汇聚奋进洪流。",
    "坚守人民立场，永葆党员本色。",
    "踏稳奋进之路，紧跟领航之旗。",
    "传承先辈风骨，建设美好中华。",
    "实干兴邦致远，初心为民长久。",
    "热爱锦绣华夏，奉献平凡人生。",
    "同心携手筑梦，聚力奔赴复兴。",
    "铭记历史来路，奋进崭新征途。",
    "把牢正确方向，竭诚服务人民。",
    "寸心寄于华夏，热忱献给山河。",
    "党建引领发展，民生幸福绵长。",
    "铸牢信仰之基，激扬爱国之情。",
    "风雨同舟共进，同心爱党兴邦。",
    "深耕为民实事，厚植家国担当。",
    "红旗照耀大地，幸福走进万家。",
    "砥砺奋斗姿态，不负盛世中华。",
    "笃守对党忠诚，践行为民宗旨。",
    "汇聚涓滴之力，铸就大国辉煌。",
    "涵养浩然正气，心怀家国苍生。",
    "追寻红色足迹，赓续奋斗荣光。",
    "强国复兴有我，奋勇一往无前。",
    "心系复兴大业，情牵百姓民生。",
    "初心如磐不改，使命在肩恒行。",
    "山河承载梦想，人民书写华章。",
    "坚定道路自信，热爱我的祖国。",
    "同心共护国土，携手造福人民。",
    "汲取红色力量，奔赴时代考场。",
    "为民排忧解难，为国添砖加瓦。",
    "紧跟时代浪潮，坚守爱国本心。",
    "聚力同心筑梦，携手向阳而行。",
    "丹心映照日月，忠诚献给党旗。",
    "万家灯火安宁，源于家国同心。",
    "树立远大志向，立志报效祖国。",
    "讲好中国故事，传递时代强音。",
    "坚守报国本分，扛起为民责任。",
    "弘扬优良传统，传承红色薪火。",
    "万众凝心聚力，华夏行稳致远。",
    "初心温暖百姓，奋斗振兴山河。",
    "不负时代召唤，不负祖国栽培。",
    "胸怀万里山河，情系万千百姓。",
    "筑牢思想根基，勇担时代使命。",
    "奋进康庄大道，感恩党的领航。",
    "平凡亦可发光，爱国不分大小。",
    "厚植红色底蕴，绽放时代芳华。",
    "永葆赤诚本色，一心服务人民。",
    "征途漫漫求索，初心久久为民。",
    "山河生生不息，信仰代代相传。",
    "笃行强国之志，常怀爱党之心。",
    "同心守护家园，携手共赴荣光。",
    "扎根华夏热土，奉献无悔青春。",
    "倾听人民心声，办好民生实事。",
    "号角催人奋进，红旗指引方向。",
    "铭记党恩浩荡，珍惜盛世安宁。",
    "勇立时代潮头，不负家国期许。",
    "团结亿万人民，共谱复兴新篇。",
    "坚守报国初心，涵养为民温情。",
    "红色精神铸魂，实干担当立身。",
    "华夏儿女同心，共赴强国征程。",
    "以奋斗护山河，以真心暖民心。",
    "信仰根植心底，爱国见于行动。",
    "携手并肩逐梦，同心向党前行。",
    "耕耘一方热土，守护一方人民。",
    "砥砺自强风骨，挺起华夏脊梁。",
    "初心不忘来路，奋斗不负今朝。",
    "党引光明大道，民筑盛世华章。",
    "常怀为民之责，常思报国之恩。",
    "凝聚磅礴力量，振兴锦绣中华。",
    "少年心怀家国，壮志奔赴山河。",
    "坚守赤子本心，紧跟党旗前行。",
    "守护国泰民安，践行初心担当。",
    "汲取奋进力量，建设幸福家园。",
    "情系中华大地，爱洒万千群众。",
    "步履坚定向前，信仰永不褪色。",
    "同心开创未来，实干成就辉煌。",
    "铭记先辈嘱托，扛起复兴担当。",
    "民生枝叶关情，初心时刻不忘。",
    "扬帆复兴蓝海，紧跟领航巨轮。",
    "弘扬时代新风，争做爱国公民。",
    "丹心献给祖国，温情送给人民。",
    "山河万里热土，此生无悔中华。",
    "夯实民生根基，稳固红色江山。",
    "永葆奋进姿态，不负人民期盼。",
    "同心汇聚暖流，真情服务群众。",
    "高举初心火炬，照亮复兴征途。",
    "笃信党的领导，共建美好神州。",
    "厚植民族底气，高扬爱国风帆。",
    "奋斗书写荣光，奉献诠释担当。",
    "初心照亮基层，实干温暖民生。",
    "万众同心筑梦，山河岁岁安康。",
    "坚守报国担当，静守为民初心。",
    "传承红色文脉，滋养家国情怀。",
    "紧跟党旗方向，奔赴光明远方。",
    "幸福源于奋斗，安宁有赖领航。",
    "勇担肩上重任，不负心中信仰。",
    "同心守望相助，共护华夏山河。",
    "初心可昭日月，忠诚永伴山河。",
    "深耕基层一线，心系百姓悲欢。",
    "以实干惠民生，以忠诚报家国。",
    "赓续奋斗血脉，奔赴复兴山海。",
    "心怀山河家国，行有责任担当。",
    "汇聚人民智慧，建设富强中国。",
    "红旗长耀山河，初心常驻心间。",
    "立志勤学奋进，长大报效中华。",
    "恪守为民宗旨，擦亮党员初心。",
    "携手乘风破浪，同心奔赴复兴。",
    "爱国贵在力行，初心重在坚守。",
    "铭记时代使命，不负锦绣山河。",
    "党暖千家万户，情系百姓安危。",
    "铸就民族风骨，挺起大国脊梁。",
    "心怀赤诚热爱，情系伟大祖国。",
    "笃行不怠奋进，矢志不渝为民。",
    "山河见证初心，岁月书写忠诚。",
    "同心凝聚力量，实干铸就辉煌。",
    "追寻初心之光，温暖百姓心房。",
    "传承奋斗薪火，续写华夏荣光。",
    "坚守为民底线，高扬信仰旗帜。",
    "逐梦山河万里，不负韶华时光。",
    "同心携手耕耘，共建盛世中华。",
    "厚植爱民底色，擦亮忠诚本色。",
    "勇担时代使命，赓续红色荣光。",
    "坚守初心阵地，守护万家祥和。",
    "牢记为民初心，勇担复兴使命。",
    "追随红色理想，书写时代答卷。",
    "同心砥砺前行，共筑华夏荣光。",
    "立足岗位奉献，矢志报国为民。",
    "信仰扎根心底，初心温暖人间。",
    "勇担时代重任，不负红色江山。",
    "凝聚青春力量，共筑强国梦想。",
    "厚植爱国根基，践行初心使命。",
    "牢记领航嘱托，勇毅奔赴前程。",
    "心系民生疾苦，胸怀家国山河。",
    "弘扬建党精神，勇毅实干争先。",
    "守护万家灯火，不负时代重托。",
    "矢志笃行不怠，一心报效家国。",
    "弘扬清风正气，永葆对党忠诚。",
    "凝聚全民力量，共绘复兴画卷。",
    "永葆奋斗本色，倾心服务人民。",
    "铭记峥嵘岁月，珍惜当下和平。",
    "汲取先辈力量，建设锦绣神州。",
    "坚守大道直行，常怀家国大爱。",
    "红旗指引前路，实干成就未来。",
    "践行初心承诺，温暖一方百姓。",
    "同心凝心聚力，共赴复兴征程。",
    "涵养赤诚之心，勇担报国之责。",
    "不负山河馈赠，不负人民期许。",
    "坚定理想信念，勇担复兴大任。",
    "传承优良家风，厚植家国情怀。",
    "践行使命担当，守护盛世中华。",
    "牢记殷殷嘱托，奋力实干争先。",
    "胸怀远大理想，扎根人民群众。",
    "弘扬奋斗精神，筑梦锦绣山河。",
    "筑牢红色阵地，传递时代强音。",
    "砥砺赤子情怀，矢志紧跟党走。",
    "同心共建家园，聚力造福民生。",
    "山河长歌浩荡，初心历久弥新。",
    "常怀敬畏之心，守护大好河山。",
    "勇立时代潮头，奉献青春力量。",
    "笃行初心使命，书写为民华章。",
    "紧跟时代号角，奋进复兴征程。",
    "赤诚献给家国，温情留给百姓。",
    "永听党话前行，同心振兴中华。",
    "党旗领航致远，初心聚力兴邦。",
    "情牵黎民冷暖，志护华夏山河。",
    "厚植赤子忠心，勇担复兴重任。",
    "赓续先辈薪火，续写时代华章。",
    "坚守为民本心，笃行报国大道。",
    "同心筑梦华夏，矢志奔赴荣光。",
    "信仰照亮征途，实干成就宏图。",
    "心系千秋伟业，情牵四海苍生。",
    "传承红色根脉，争做时代先锋。",
    "紧跟领航方向，共赴盛世新程。",
    "心怀家国大义，恪守为民初心。",
    "聚力凝心奋进，携手振兴神州。",
    "深耕民生实事，厚筑家国根基。",
    "红旗昭昭引路，热血代代相传。",
    "常怀济世情怀，永葆忠诚底色。",
    "不负时代召唤，勇担强国使命。",
    "山河因党锦绣，百姓因福安康。",
    "凝聚青春力量，守护锦绣中华。",
    "笃行为民善举，厚扬爱国新风。",
    "铭记百年征程，砥砺奋进初心。",
    "矢志忠于信仰，倾情服务人民。",
    "共护万里疆土，同迎盛世朝阳。",
    "弘扬民族正气，挺起大国脊梁。",
    "初心扎根乡土，大爱温暖民心。",
    "勇踏复兴长路，甘当时代基石。",
    "党恩润泽九州，民心汇聚千钧。",
    "以行诠释忠诚，以爱守护家国。",
    "守望千秋故土，共筑百年梦想。",
    "涵养浩然风骨，胸怀万里山河。",
    "奋进康庄大道，不负盛世韶华。",
    "深耕红色沃土，激扬奋进豪情。",
    "坚守初心阵地，厚植家国情怀。",
    "同心守望相助，聚力强国兴邦。",
    "步履追随党旗，丹心献给祖国。",
    "善办民生小事，扛起时代担当。",
    "薪火代代赓续，伟业步步攀登。",
    "胸怀星辰大海，心系烟火人间。",
    "笃守初心正道，勇担时代使命。",
    "汇聚凡人微光，点亮华夏星河。",
    "礼赞百年风华，奔赴万里新程。",
    "为民纾困解难，为国添彩增辉。",
    "红旗高扬九州，初心温暖万家。",
    "传承奋斗精神，厚植报国情怀。",
    "坚定前行方向，不负人民重托。",
    "同守红色江山，共绘复兴蓝图。",
    "常怀报国热忱，静守为民温情。",
    "少年胸怀家国，壮志奔赴远方。",
    "实干浇灌幸福，初心铸就辉煌。",
    "追随真理之光，守护国泰民安。",
    "弘扬时代正气，凝聚民族力量。",
    "扎根基层一线，情系百姓万家。",
    "矢志紧跟党走，同心逐梦前行。",
    "山河铺展画卷，奋斗书写荣光。",
    "坚守赤诚本心，勇担复兴之责。",
    "同心汇聚暖流，携手奔赴新程。",
    "铭记先辈宏愿，建设锦绣神州。",
    "筑牢思想根基，擦亮忠诚底色。",
    "情系一方水土，爱护亿万同胞。",
    "号角声声催征，红旗猎猎领航。",
    "笃行不怠追梦，矢志不渝为民。",
    "厚扬红色文化，滋养家国初心。",
    "携手乘风破浪，共护盛世安宁。",
    "初心可昭日月，大爱长润山河。",
    "立足本职岗位，奉献家国人民。",
    "汲取奋进力量，勇毅阔步向前。",
    "江山承载梦想，奋斗开创未来。",
    "恪守为民宗旨，常怀爱党之心。",
    "同心共圆国梦，携手共谱新篇。",
    "铭记来路艰辛，珍惜今朝盛世。",
    "信仰根植心底，担当见于行动。",
    "深耕民生福祉，守护万家灯火。",
    "丹心不负家国，热忱温暖苍生。",
    "弘扬优良新风，争做爱国公民。",
    "聚力团结奋进，昂首振兴中华。",
    "征途风正帆满，华夏步履铿锵。",
    "坚守报国初心，勇扛时代重任。",
    "传承英雄风骨，厚植家国担当。",
    "心系复兴蓝图，情牵百姓安危。",
    "少年强国有我，青春向党启航。",
    "实干不负时代，忠诚不负人民。",
    "同沐党的光辉，共享盛世祥和。",
    "追寻红色足迹，传承奋斗精神。",
    "胸怀家国山河，肩担岁月荣光。",
    "笃行报国之志，厚修为民之心。",
    "万众同心同向，巨轮破浪远航。",
    "守护山河无恙，期盼百姓安康。",
    "铸牢民族同心，聚力复兴伟业。",
    "初心温暖街巷，奋斗点亮神州。",
    "紧跟时代步伐，永葆爱党赤诚。",
    "笔墨书写家国，丹心告白山河。",
    "聚力实干兴邦，倾心惠民利民。",
    "红旗映照初心，奋斗筑就辉煌。",
    "常怀敬畏山河，永怀赤诚家国。",
    "勇立时代潮头，书写青春答卷。",
    "厚植家国沃土，绽放时代芳华。",
    "同心携手耕耘，共筑华夏荣光。",
    "坚守正道直行，永葆赤子情怀。",
    "为民尽心尽力，为国尽责尽忠。",
    "赓续红色血脉，守护锦绣河山。",
    "凝聚民心所向，奔赴复兴远方。",
    "山河岁岁安宁，初心久久不改。",
    "笃信党的引领，齐心共建家园。",
    "弘扬奉献精神，涵养家国大爱。",
    "勇担肩头使命，不负心中信仰。",
    "情融万家烟火，志在万里山河。",
    "初心如磐笃定，使命永记心间。",
    "汲取先辈智慧，开创时代新篇。",
    "同心守望山河，携手造福苍生。",
    "奋斗点亮理想，忠诚守护家国。",
    "厚植爱民情怀，砥砺报国担当。",
    "盛世来之不易，爱国贵在躬行。",
    "党旗指引征途，民心汇聚力量。",
    "心怀滚烫信仰，奔赴璀璨前程。",
    "深耕基层沃土，绽放为民芳华。",
    "华夏儿女同心，共赴强国征途。",
    "不负山河厚望，不负时代初心。",
    "讲好中国故事，传递家国心声。",
    "坚守红色信仰，勇毅实干争先。",
    "万家灯火璀璨，一片丹心向党。",
    "聚力乘风破浪，同心续写华章。",
    "常怀感恩党恩，矢志报效祖国。",
    "守护民族根魂，共筑复兴丰碑。",
    "笃行青春担当，不负伟大时代。",
    "民心连着党心，家国紧紧相依。",
    "踏稳奋进步履，擦亮爱国初心。",
    "弘扬清风正气，涵养家国新风。",
    "同心耕耘希望，共迎华夏腾飞。",
    "初心献给人民，热血献给祖国。",
    "铭记时代嘱托，勇毅砥砺前行。",
    "汇聚涓滴善力，铸就盛世丰碑。",
    "红旗漫卷山河，信仰生生不息。",
    "立足平凡岗位，彰显不凡担当。",
    "胸怀千秋梦想，心系亿兆民生。",
    "传承时代薪火，奔赴复兴山海。",
    "恪守忠诚本分，践行为民初心。",
    "同守一方热土，共护一国安宁。",
    "奋斗不负韶华，赤诚不负家国。",
    "厚植文化自信，高扬爱国风帆。",
    "号角唤醒初心，奋斗成就梦想。",
    "丹心映照山河，温情温暖人间。",
    "紧跟时代浪潮，坚守报国本心。",
    "聚力同心向善，携手筑梦兴邦。",
    "山河承载信仰，奋斗续写辉煌。",
    "少年立志报国，青春不负家国。",
    "深耕惠民之举，厚固强国之基。",
    "初心不改航向，奋斗永不停歇。",
    "弘扬先辈精神，勇担时代使命。",
    "同心拥抱盛世，携手奔赴荣光。",
    "信仰如灯长明，初心如磐永固。",
    "情系华夏故土，爱伴岁岁朝夕。",
    "实干铺就坦途，初心温暖民心。",
    "共护红色文脉，同传家国大爱。",
    "勇担复兴重任，不负先辈期许。",
    "常怀为民之念，常思报国之行。",
    "红旗照亮前路，同心奔赴远方。",
    "厚养浩然正气，勇担家国担当。",
    "扎根华夏大地，书写无悔青春。",
    "聚力团结一心，共筑盛世中华。",
    "初心照亮前路，大爱润泽民生。",
    "铭记峥嵘过往，奋进崭新征程。",
    "笃守家国正道，弘扬时代新风。",
    "为民甘于奉献，为国勇于担当。",
    "赓续英雄志气，振兴锦绣中华。",
    "同心凝聚力量，实干开辟新局。",
    "心怀家国天下，情系百姓安康。",
    "追随党旗方向，绽放时代光芒。",
    "厚植奋斗底色，擦亮爱国名片。",
    "万众携手同行，山河岁岁繁荣。",
    "初心根植乡土，大爱泽被四方。",
    "勇闯时代征途，誓圆复兴梦想。",
    "弘扬建党伟力，聚力强国宏图。",
    "守护大好河山，奉献赤诚丹心。",
    "笃行实干兴邦，倾心服务群众。",
    "少年心怀远志，立志报效家国。",
    "信仰凝聚力量，奋斗铸就辉煌。",
    "同心共担使命，携手共创辉煌。",
    "常怀赤子之心，守护华夏安宁。",
    "传承家国文脉，厚植报国初心。",
    "紧跟党的号召，勇毅实干前行。",
    "山河写满热爱，奋斗奔赴荣光。",
    "深耕民生一线，厚筑幸福根基。",
    "初心忠于信仰，行动服务人民。",
    "聚力扬帆奋进，同心筑梦神州。",
    "铭记时代使命，永葆爱国热忱。",
    "红旗扎根沃土，初心温暖万家。",
    "勇担青春使命，守护锦绣山河。",
    "笃行大道致远，常怀家国深情。",
    "同心守护和平，携手振兴中华。",
    "奏响红色旋律，传递时代强音。",
    "实干书写担当，忠诚映照初心。",
    "胸怀复兴伟业，情系万千百姓。",
    "赓续奋斗基因，勇毅奔赴新程。",
    "扎根人民之中，汲取奋进力量。",
    "丹心长昭日月，浩气永壮山河。",
    "同心逐梦山海，携手共赴荣光。",
    "坚守报国之志，常怀为民之情。",
    "弘扬民族精神，凝聚复兴伟力。",
    "初心历久弥坚，征途步履不停。",
    "共绘山河盛景，同筑时代丰碑。",
    "永怀赤子之心，矢志强国有我。",
]

# 名单以同目录的 node_names.txt 为准（一行一条）：文件存在且非空时，排列顺序按文件来；
# 上面的内置名单只作文件缺失时的兜底。
try:
    _names_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'node_names.txt')
    with open(_names_path, encoding='utf-8') as _nf:
        _file_names = [line.strip() for line in _nf if line.strip()]
    if _file_names:
        FIXED_NODE_NAMES = _file_names
except Exception:
    pass

# ===== 网络会话配置 =====
# 配置HTTP会话，优化网络请求性能
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Cache-Control': 'max-age=0'
})

# 配置连接池 - 优化网络连接性能
adapter = requests.adapters.HTTPAdapter(
    pool_connections=10,    # 连接池大小
    pool_maxsize=20,         # 最大连接数
    max_retries=3           # 最大重试次数
)
session.mount('http://', adapter)
session.mount('https://', adapter)

# ===== 缓存管理模块 =====
# 智能缓存系统，支持TTL机制和自动清理

def load_region_cache():
    """
    加载地区信息缓存
    
    从Cache.json文件中加载已缓存的IP地理位置信息，
    如果文件不存在或加载失败，则使用空缓存。
    
    Returns:
        None: 直接修改全局变量region_cache
    """
    global region_cache
    if os.path.exists('Cache.json'):
        try:
            with open('Cache.json', 'r', encoding='utf-8') as f:
                region_cache = json.load(f)
            logger.info(f"📦 成功加载缓存文件，包含 {len(region_cache)} 个条目")
        except Exception as e:
            logger.warning(f"⚠️ 加载缓存文件失败: {str(e)[:50]}")
            region_cache = {}
    else:
        logger.info("📦 缓存文件不存在，使用空缓存")
        region_cache = {}

def save_region_cache():
    """
    保存地区信息缓存
    
    将当前内存中的地区缓存数据保存到Cache.json文件中，
    用于下次启动时快速加载已查询过的IP地理位置信息。
    
    Returns:
        None: 直接保存到文件，无返回值
    """
    try:
        with open('Cache.json', 'w', encoding='utf-8') as f:
            json.dump(region_cache, f, ensure_ascii=False)
        logger.info(f"💾 成功保存缓存文件，包含 {len(region_cache)} 个条目")
    except Exception as e:
        logger.error(f"❌ 保存缓存文件失败: {str(e)[:50]}")
        pass

def is_cache_valid(timestamp, ttl_hours=24):
    """
    检查缓存是否有效
    
    Args:
        timestamp (str): 缓存时间戳（ISO格式）
        ttl_hours (int): 缓存有效期（小时），默认24小时
    
    Returns:
        bool: True表示缓存有效，False表示已过期
    """
    if not timestamp:
        return False
    cache_time = datetime.fromisoformat(timestamp)
    return datetime.now() - cache_time < timedelta(hours=ttl_hours)

def clean_expired_cache():
    """
    清理过期缓存和限制缓存大小
    
    自动清理过期的缓存条目，并限制缓存大小以防止内存溢出。
    支持TTL机制和LRU策略。
    
    Returns:
        None: 直接修改全局变量region_cache
    """
    global region_cache
    current_time = datetime.now()
    expired_keys = []
    
    # 清理过期缓存
    for ip, data in region_cache.items():
        if isinstance(data, dict) and 'timestamp' in data:
            cache_time = datetime.fromisoformat(data['timestamp'])
            if current_time - cache_time >= timedelta(hours=CONFIG["cache_ttl_hours"]):
                expired_keys.append(ip)
    
    for key in expired_keys:
        del region_cache[key]
    
    # 限制缓存大小（最多保留1000个条目）
    if len(region_cache) > 1000:
        # 按时间排序，删除最旧的条目
        sorted_items = sorted(region_cache.items(), 
                            key=lambda x: x[1].get('timestamp', '') if isinstance(x[1], dict) else '')
        items_to_remove = len(region_cache) - 1000
        for i in range(items_to_remove):
            del region_cache[sorted_items[i][0]]
        logger.info(f"缓存过大，清理了 {items_to_remove} 个旧条目")
    
    if expired_keys:
        logger.info(f"清理了 {len(expired_keys)} 个过期缓存条目")

# ===== 文件操作模块 =====
# 文件管理功能，包括删除、创建等操作

def delete_file_if_exists(file_path):
    """
    删除指定文件（如果存在）
    
    在程序开始前清理旧的结果文件，避免结果累积。
    
    Args:
        file_path (str): 要删除的文件路径
    
    Returns:
        None: 无返回值，仅执行删除操作
    """
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            logger.info(f"🗑️ 已删除原有文件: {file_path}")
        except Exception as e:
            logger.warning(f"⚠️ 删除文件失败: {str(e)}")

# ===== 网络检测模块 =====
# 网络连接测试功能，包括TCP连接、延迟测试、带宽测试等

def quick_filter_ip(ip):
    """
    快速筛选IP - 基础TCP连接测试
    
    对IP地址进行快速的TCP连接测试，快速剔除明显不可用的IP，
    这是第一轮筛选，用于减少后续深度测试的工作量。
    
    Args:
        ip (str): 要测试的IP地址
    
    Returns:
        tuple: (是否可用, 延迟毫秒数) - (bool, int)
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0)
    except (ValueError, AttributeError):
        return (False, 0)
    
    min_delay = float('inf')
    success_count = 0
    
    for port in CONFIG["test_ports"]:
        try:
            if not isinstance(port, int) or not (1 <= port <= 65535):
                continue
                
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                start_time = time.time()
                
                if s.connect_ex((ip, port)) == 0:
                    delay = round((time.time() - start_time) * 1000)
                    min_delay = min(min_delay, delay)
                    success_count += 1
                    
                    if delay < 200:
                        return (True, delay)
        except (socket.timeout, socket.error, OSError):
            continue
        except Exception:
            continue
    
    if success_count > 0:
        return (True, min_delay)
    
    return (False, 0)

def test_ip_bandwidth_only(ip, current, total):
    """
    通过HTTP下载测试IP带宽性能
    
    使用真实的HTTP下载测试来测量IP的带宽性能，
    通过下载指定大小的文件来评估网络速度。
    
    Args:
        ip (str): 要测试的IP地址
        current (int): 当前测试序号
        total (int): 总测试数量
    
    Returns:
        tuple: (是否成功, 带宽Mbps, 延迟毫秒) - (bool, float, float)
    """
    try:
        # 验证IP地址格式
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0, 0)
        
        # 使用真实的下载测试来测量带宽
        test_size_bytes = CONFIG["bandwidth_test_size_mb"] * 1024 * 1024
        test_urls = [
            # 使用一些公开的测试文件
            f"https://speed.cloudflare.com/__down?bytes={test_size_bytes}",  # 可配置大小测试文件
            f"https://httpbin.org/bytes/{test_size_bytes}",  # 可配置大小测试文件
        ]
        
        best_speed = 0
        best_latency = 0
        
        # 使用配置的测试次数
        test_count = CONFIG["bandwidth_test_count"]
        for test_attempt in range(test_count):
            for url in test_urls:
                try:
                    start_time = time.time()
                    
                    # 发送HTTP请求测试带宽
                    response = session.get(
                        url, 
                        timeout=15,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                        stream=True
                    )
                    
                    if response.status_code == 200:
                        # 测量下载速度
                        data_size = 0
                        start_download = time.time()
                        
                        # 下载数据块来测试速度
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                data_size += len(chunk)
                                # 限制测试时间，避免过长时间
                                if time.time() - start_download > 10:  # 最多测试10秒
                                    break
                                # 如果下载了足够的数据就停止
                                if data_size > 10 * 1024 * 1024:  # 10MB
                                    break
                        
                        download_time = time.time() - start_download
                        latency = (start_download - start_time) * 1000  # 延迟
                        
                        if download_time > 0 and data_size > 0:
                            # 计算速度 (Mbps)
                            speed_mbps = (data_size * 8) / (download_time * 1000000)
                            best_speed = max(best_speed, speed_mbps)
                            best_latency = latency if best_latency == 0 else min(best_latency, latency)
                            
                            # 如果速度很好，可以提前返回
                            if speed_mbps > 5:  # 超过5Mbps就认为很好
                                logger.info(f"⚡ [{current}/{total}] {ip}（带宽综合速度：{best_speed:.2f}Mbps）")
                                return (True, best_speed, best_latency)
                
                except Exception as e:
                    logger.debug(f"IP {ip} 带宽测试失败: {str(e)[:50]}")
                    continue
        
        if best_speed > 0:
            logger.info(f"⚡ [{current}/{total}] {ip}（带宽综合速度：{best_speed:.2f}Mbps）")
            return (True, best_speed, best_latency)
        else:
            # 如果带宽测试失败，返回延迟测试结果
            is_available, latency = test_ip_availability(ip)
            if is_available:
                logger.info(f"⚡ [{current}/{total}] {ip}（带宽测试失败，使用延迟作为替代指标）")
                return (True, 0, latency)  # 返回0表示带宽测试失败，但延迟可用
            else:
                logger.info(f"⚡ [{current}/{total}] {ip}（带宽测试失败）")
                return (False, 0, 0)
            
    except Exception as e:
        logger.error(f"IP {ip} 带宽测试异常: {str(e)[:50]}")
        return (False, 0, 0)

def calculate_score(min_delay, avg_delay, bandwidth, stability):
    """
    计算综合评分 - 结合延迟、带宽、稳定性
    
    根据IP的延迟、带宽和稳定性等指标计算综合评分，
    用于智能排序和推荐最佳IP。
    
    Args:
        min_delay (float): 最小延迟（毫秒）
        avg_delay (float): 平均延迟（毫秒）
        bandwidth (float): 带宽（Mbps）
        stability (float): 稳定性指标
    
    Returns:
        float: 综合评分（0-100分）
    """
    # 延迟评分 (0-40分) - 延迟越低分数越高
    if min_delay <= 50:
        delay_score = 40
    elif min_delay <= 100:
        delay_score = 35
    elif min_delay <= 200:
        delay_score = 30
    elif min_delay <= 300:
        delay_score = 25
    else:
        delay_score = max(0, 20 - (min_delay - 300) / 10)
    
    # 带宽评分 (0-30分) - 带宽越高分数越高
    if bandwidth >= 50:
        bandwidth_score = 30
    elif bandwidth >= 20:
        bandwidth_score = 25
    elif bandwidth >= 10:
        bandwidth_score = 20
    elif bandwidth >= 5:
        bandwidth_score = 15
    else:
        bandwidth_score = max(0, bandwidth * 3)
    
    # 稳定性评分 (0-30分) - 稳定性越高分数越高
    stability_score = min(30, stability * 0.3)
    
    # 综合评分
    total_score = delay_score + bandwidth_score + stability_score
    
    return round(total_score, 1)

def latency_filter_ips(ip_results, percentage=30):
    """
    延迟排名筛选 - 取前N%的IP
    
    根据延迟性能对IP进行排名筛选，只保留延迟最低的前N%的IP，
    用于减少后续深度测试的工作量。
    
    Args:
        ip_results (list): IP测试结果列表
        percentage (int): 保留百分比，默认30%
    
    Returns:
        list: 筛选后的IP结果列表
    """
    if not ip_results:
        return []
    
    # 按延迟排序
    sorted_results = sorted(ip_results, key=lambda x: x[1])  # 按min_delay排序
    
    # 计算要保留的数量
    keep_count = max(1, int(len(sorted_results) * percentage / 100))
    
    # 显示筛选结果
    logger.info(f"🔍 延迟排名前{percentage}%筛选：从 {len(sorted_results)} 个IP中筛选出 {keep_count} 个IP")
    
    # 显示筛选结果
    for i, (ip, min_delay, avg_delay, stability) in enumerate(sorted_results[:keep_count], 1):
        logger.info(f"📊 {ip}（延迟排名第{i}位：{avg_delay:.1f}ms）")
    
    return sorted_results[:keep_count]

def test_ip_availability(ip):
    """
    TCP Socket检测IP可用性 - 支持多端口自定义
    
    使用TCP Socket连接测试IP的可用性和延迟，
    支持配置多个测试端口，返回最佳连接结果。
    
    Args:
        ip (str): 要测试的IP地址
    
    Returns:
        tuple: (是否可用, 延迟毫秒数) - (bool, int)
    """
    # 验证IP地址格式
    try:
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0)
    except (ValueError, AttributeError):
        return (False, 0)
    
    # 检查测试端口配置
    if not CONFIG["test_ports"] or not isinstance(CONFIG["test_ports"], list):
        logger.warning(f"⚠️ 测试端口配置无效，跳过IP {ip}")
        return (False, 0)
    
    min_delay = float('inf')
    success_count = 0
    
    # 遍历配置的测试端口
    for port in CONFIG["test_ports"]:
        try:
            # 验证端口号
            if not isinstance(port, int) or not (1 <= port <= 65535):
                logger.warning(f"⚠️ 无效端口号 {port}，跳过")
                continue
                
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)  # 3秒超时
                start_time = time.time()
                
                # 尝试TCP连接
                if s.connect_ex((ip, port)) == 0:
                    delay = round((time.time() - start_time) * 1000)
                    min_delay = min(min_delay, delay)
                    success_count += 1
                    
                    # 如果延迟很好，立即返回最佳结果
                    if delay < 200:
                        return (True, delay)
        except (socket.timeout, socket.error, OSError):
            continue  # 继续测试下一个端口
        except Exception as e:
            logger.debug(f"IP {ip} 端口 {port} 检测异常: {str(e)[:30]}")
            continue
    
    # 返回最佳结果
    if success_count > 0:
        return (True, min_delay)
    
    return (False, 0)

# ===== 地区识别模块 =====
# IP地理位置识别功能，支持多API源和智能缓存

def get_ip_region(ip):
    """
    优化的IP地区识别（支持缓存TTL）
    
    通过多个API源查询IP的地理位置信息，支持智能缓存机制，
    避免重复查询，提升查询效率。
    
    Args:
        ip (str): 要查询的IP地址
    
    Returns:
        str: 国家代码（如'US', 'CN', 'JP'等）
    """
    # 检查缓存是否有效
    if ip in region_cache:
        cached_data = region_cache[ip]
        if isinstance(cached_data, dict) and 'timestamp' in cached_data:
            if is_cache_valid(cached_data['timestamp'], CONFIG["cache_ttl_hours"]):
                logger.info(f"📦 IP {ip} 地区信息从缓存获取: {cached_data['region']}")
                return cached_data['region']
        else:
            # 兼容旧格式缓存
            logger.info(f"📦 IP {ip} 地区信息从缓存获取（旧格式）: {cached_data}")
            return cached_data
    
    # 尝试主要API（免费版本）
    logger.info(f"🌐 IP {ip} 开始API查询（主要API: ipinfo.io lite）...")
    try:
        resp = session.get(f'https://api.ipinfo.io/lite/{ip}?token=2cb674df499388', timeout=CONFIG["api_timeout"])
        if resp.status_code == 200:
            data = resp.json()
            country_code = data.get('country_code', '').upper()
            if country_code:
                region_cache[ip] = {
                    'region': country_code,
                    'timestamp': datetime.now().isoformat()
                }
                logger.info(f"✅ IP {ip} 主要API识别成功: {country_code}（来源：API查询）")
                return country_code
        else:
            logger.warning(f"⚠️ IP {ip} 主要API返回状态码: {resp.status_code}")
    except Exception as e:
        logger.error(f"❌ IP {ip} 主要API识别失败: {str(e)[:30]}")
        pass
    
    # 尝试备用API
    logger.info(f"🌐 IP {ip} 尝试备用API（ip-api.com）...")
    try:
        resp = session.get(f'http://ip-api.com/json/{ip}?fields=countryCode', timeout=CONFIG["api_timeout"])
        if resp.json().get('status') == 'success':
            country_code = resp.json().get('countryCode', '').upper()
            if country_code:
                region_cache[ip] = {
                    'region': country_code,
                    'timestamp': datetime.now().isoformat()
                }
                logger.info(f"✅ IP {ip} 备用API识别成功: {country_code}")
                return country_code
        else:
            logger.warning(f"⚠️ IP {ip} 备用API返回状态: {resp.json().get('status', 'unknown')}")
    except Exception as e:
        logger.error(f"❌ IP {ip} 备用API识别失败: {str(e)[:30]}")
        pass
    
    # 失败返回Unknown
    logger.warning(f"❌ IP {ip} 所有API识别失败，标记为Unknown")
    region_cache[ip] = {
        'region': 'Unknown',
        'timestamp': datetime.now().isoformat()
    }
    return 'Unknown'

def get_country_name(code):
    """
    根据国家代码获取中文名称
    
    将ISO国家代码转换为中文名称，用于用户友好的显示。
    
    Args:
        code (str): 国家代码（如'US', 'CN'等）
    
    Returns:
        str: 中文国家名称
    """
    return COUNTRY_MAPPING.get(code, code)

# ===== 并发处理模块 =====
# 高并发网络测试功能，支持多线程并发处理

def test_ips_concurrently(ips, max_workers=None):
    """
    超快并发检测IP可用性（防卡住优化）
    
    使用ThreadPoolExecutor实现并发处理，大幅提升检测效率。
    支持批量处理和超时保护，避免程序卡住。
    
    Args:
        ips (list): 要测试的IP地址列表
        max_workers (int): 最大并发线程数，默认使用配置值
    
    Returns:
        list: 可用IP列表，格式为[(ip, delay), ...]
    """
    if max_workers is None:
        max_workers = CONFIG["max_workers"]
    
    logger.info(f"📡 开始并发检测 {len(ips)} 个IP，使用 {max_workers} 个线程")
    available_ips = []
    
    # 使用更小的批次，避免卡住
    batch_size = CONFIG["batch_size"]  # 使用配置的批次大小
    start_time = time.time()
    
    for i in range(0, len(ips), batch_size):
        batch_ips = ips[i:i+batch_size]
        batch_num = i//batch_size + 1
        total_batches = (len(ips)-1)//batch_size + 1
        
        logger.info(f"📡 处理批次 {batch_num}/{total_batches}，包含 {len(batch_ips)} 个IP")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交批次任务，添加超时保护
            future_to_ip = {executor.submit(test_ip_availability, ip): ip for ip in batch_ips}
            
            # 处理完成的任务
            batch_completed = 0
            for future in as_completed(future_to_ip, timeout=30):  # 添加30秒超时保护
                ip = future_to_ip[future]
                batch_completed += 1
                completed = i + batch_completed
                elapsed = time.time() - start_time
                
                try:
                    is_available, delay = future.result()
                    if is_available:
                        available_ips.append((ip, delay))
                        logger.info(f"🎯 [{completed}/{len(ips)}] {ip}（TCP Ping 综合延迟：{delay:.1f}ms）")
                    else:
                        logger.info(f"[{completed}/{len(ips)}] {ip} ❌ 不可用 - 耗时: {elapsed:.1f}s")
                    
                    # 添加小延迟确保日志顺序
                    time.sleep(0.01)  # 10ms延迟
                except Exception as e:
                    logger.error(f"[{completed}/{len(ips)}] {ip} ❌ 检测出错: {str(e)[:30]} - 耗时: {elapsed:.1f}s")
                    
                    # 添加小延迟确保日志顺序
                    time.sleep(0.01)  # 10ms延迟
        
        # 批次间短暂休息，避免过度占用资源
        if i + batch_size < len(ips):
            time.sleep(0.2)  # 减少休息时间
    
    total_time = time.time() - start_time
    logger.info(f"📡 并发检测完成，发现 {len(available_ips)} 个可用IP，总耗时: {total_time:.1f}秒")
    return available_ips

def get_regions_concurrently(ips, max_workers=None):
    """
    并发识别IP地理位置，保持日志输出顺序
    
    使用多线程并发查询IP的地理位置信息，同时保持日志输出的顺序性，
    提升查询效率的同时保证用户体验。
    
    Args:
        ips (list): IP地址列表，格式为[(ip, min_delay, avg_delay), ...]
        max_workers (int): 最大并发线程数，默认使用配置值
    
    Returns:
        list: 地区识别结果，格式为[(ip, region_code, min_delay, avg_delay), ...]
    """
    if max_workers is None:
        max_workers = CONFIG["max_workers"]
    
    logger.info(f"🌍 开始并发地区识别 {len(ips)} 个IP，使用 {max_workers} 个线程")
    results = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_ip = {executor.submit(get_ip_region, ip): (ip, min_delay, avg_delay) for ip, min_delay, avg_delay in ips}
        
        # 先收集所有结果，不输出日志
        for i, (ip, min_delay, avg_delay) in enumerate(ips, 1):
            future = None
            # 找到对应的future
            for f, (f_ip, f_min_delay, f_avg_delay) in future_to_ip.items():
                if f_ip == ip and f_min_delay == min_delay and f_avg_delay == avg_delay:
                    future = f
                    break
            
            if future:
                try:
                    region_code = future.result()
                    results.append((ip, region_code, min_delay, avg_delay))
                    
                    # 只在API查询时等待，缓存查询不需要等待
                    if i % 10 == 0:  # 每10个IP等待一次，减少等待频率
                        time.sleep(CONFIG["query_interval"])
                except Exception as e:
                    logger.warning(f"地区识别失败 {ip}: {str(e)[:50]}")
                    results.append((ip, 'Unknown', min_delay, avg_delay))
        
        # 所有结果收集完成后，输出地区识别结果
        for i, (ip, region_code, min_delay, avg_delay) in enumerate(results, 1):
            logger.info(f"📦 [{i}/{len(ips)}] {ip} -> {region_code}")
                    
    
    total_time = time.time() - start_time
    logger.info(f"🌍 地区识别完成，处理了 {len(results)} 个IP，总耗时: {total_time:.1f}秒")
    return results


# ===== 域名解析模块（IP 唯一来源） =====
# 只解析 CONFIG["domains"] 里的三个域名：
# - 无 ECS 多源 DoH（Cloudflare/Google/doh.pub/nextdns）拿基准结果并跟 CNAME；
# - 再逐个内嵌 ECS 子网带 edns_client_subnet 向 Google DoH 查询，
#   连域名本身一起扫（有的域名带 ECS 时权威直接回该线路 A 池，只扫 CNAME 目标会漏）；
# - 只放行公网 IPv4（127.0.0.1 那类回环/私网/198.18 假 IP 直接屏蔽），不用 IPv6。
GOOGLE_DOH = "https://dns.google/resolve"
PLAIN_DOH = [
    "https://cloudflare-dns.com/dns-query",
    GOOGLE_DOH,
    "https://doh.pub/dns-query",
    "https://dns.nextdns.io/dns-query",
]
ECS_WORKERS = 24


def _doh_answers(name, base=GOOGLE_DOH, ecs=None):
    params = {"name": name, "type": "A"}
    if ecs:
        params["edns_client_subnet"] = ecs
    try:
        resp = session.get(base, params=params, headers={"accept": "application/dns-json"}, timeout=15)
        if resp.status_code != 200:
            return []
        return resp.json().get("Answer") or []
    except Exception:
        return []


def _is_public_ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global and not ip.is_multicast


def _collect_answers(answers, ips, cnames):
    for ans in answers:
        data = str(ans.get("data", "")).strip().rstrip(".")
        if ans.get("type") == 1:
            if _is_public_ipv4(data):
                ips.add(data)
        elif ans.get("type") == 5:
            cnames.add(data)


def _final_targets(domain):
    targets = {domain}
    for _ in range(8):
        nxt = set()
        for name in list(targets):
            ips, cnames = set(), set()
            for base in PLAIN_DOH:
                _collect_answers(_doh_answers(name, base), ips, cnames)
            nxt |= cnames
        if not nxt:
            break
        targets = nxt
    return targets


ECS_SUBNETS = [
    "1.1.1.0/24",
    "1.10.128.0/24",
    "5.228.0.0/24",
    "8.8.8.0/24",
    "9.9.9.0/24",
    "23.208.0.0/24",
    "24.80.0.0/24",
    "31.13.24.0/24",
    "41.205.192.0/24",
    "58.20.0.0/24",
    "58.20.64.0/24",
    "58.20.127.0/24",
    "58.20.128.0/24",
    "58.20.192.0/24",
    "58.97.0.0/24",
    "58.240.0.0/24",
    "58.240.57.0/24",
    "58.240.64.0/24",
    "58.240.128.0/24",
    "58.240.192.0/24",
    "60.191.0.0/24",
    "60.191.64.0/24",
    "60.191.128.0/24",
    "60.191.192.0/24",
    "60.217.0.0/24",
    "60.217.64.0/24",
    "60.217.128.0/24",
    "60.217.192.0/24",
    "61.8.0.0/24",
    "61.10.0.0/24",
    "61.64.127.0/24",
    "61.91.190.0/24",
    "61.95.185.0/24",
    "61.128.0.0/24",
    "61.128.64.0/24",
    "61.128.97.0/24",
    "61.128.128.0/24",
    "61.128.192.0/24",
    "61.132.163.0/24",
    "61.139.2.0/24",
    "61.144.0.0/24",
    "61.144.64.0/24",
    "61.144.128.0/24",
    "61.144.192.0/24",
    "61.157.0.0/24",
    "61.157.64.0/24",
    "61.157.128.0/24",
    "61.157.158.0/24",
    "61.157.192.0/24",
    "61.160.0.0/24",
    "61.160.64.0/24",
    "61.160.128.0/24",
    "61.160.192.0/24",
    "61.161.0.0/24",
    "61.161.64.0/24",
    "61.161.128.0/24",
    "61.161.192.0/24",
    "61.177.0.0/24",
    "61.177.64.0/24",
    "61.177.128.0/24",
    "61.177.192.0/24",
    "61.190.0.0/24",
    "61.190.64.0/24",
    "61.190.128.0/24",
    "61.190.192.0/24",
    "61.238.180.0/24",
    "62.40.34.0/24",
    "64.6.64.0/24",
    "70.24.0.0/24",
    "76.76.2.0/24",
    "81.2.69.0/24",
    "82.102.128.0/24",
    "86.98.0.0/24",
    "88.221.12.0/24",
    "89.107.129.0/24",
    "94.200.16.0/24",
    "99.224.0.0/24",
    "101.226.4.0/24",
    "103.86.96.0/24",
    "104.16.0.0/24",
    "105.224.0.0/24",
    "106.161.232.0/24",
    "109.252.114.0/24",
    "111.26.0.0/24",
    "111.26.64.0/24",
    "111.26.128.0/24",
    "111.26.192.0/24",
    "112.50.0.0/24",
    "112.50.64.0/24",
    "112.50.84.0/24",
    "112.50.128.0/24",
    "112.50.192.0/24",
    "112.96.0.0/24",
    "112.96.64.0/24",
    "112.96.128.0/24",
    "112.96.192.0/24",
    "112.122.10.0/24",
    "113.57.0.0/24",
    "113.57.249.0/24",
    "113.58.0.0/24",
    "113.59.0.0/24",
    "113.60.0.0/24",
    "113.61.0.0/24",
    "113.62.0.0/24",
    "113.64.0.0/24",
    "113.65.0.0/24",
    "114.114.114.0/24",
    "115.238.81.0/24",
    "117.102.61.0/24",
    "117.136.0.0/24",
    "117.136.6.0/24",
    "117.136.64.0/24",
    "117.136.128.0/24",
    "117.136.192.0/24",
    "117.158.0.0/24",
    "117.158.64.0/24",
    "117.158.128.0/24",
    "117.158.192.0/24",
    "117.187.0.0/24",
    "117.187.64.0/24",
    "117.187.128.0/24",
    "117.187.192.0/24",
    "119.29.29.0/24",
    "120.196.0.0/24",
    "120.196.64.0/24",
    "120.196.128.0/24",
    "120.196.165.0/24",
    "120.196.192.0/24",
    "120.208.0.0/24",
    "120.208.64.0/24",
    "120.208.128.0/24",
    "120.208.192.0/24",
    "121.88.172.0/24",
    "121.101.220.0/24",
    "123.125.0.0/24",
    "123.125.64.0/24",
    "123.125.81.0/24",
    "123.125.128.0/24",
    "123.125.192.0/24",
    "124.65.0.0/24",
    "124.65.64.0/24",
    "124.65.128.0/24",
    "124.65.192.0/24",
    "124.88.0.0/24",
    "124.88.64.0/24",
    "124.88.128.0/24",
    "124.88.192.0/24",
    "125.64.0.0/24",
    "125.64.108.0/24",
    "125.69.0.0/24",
    "125.69.40.0/24",
    "125.71.0.0/24",
    "125.76.0.0/24",
    "125.80.0.0/24",
    "125.86.0.0/24",
    "125.93.0.0/24",
    "126.0.0.0/24",
    "133.11.1.0/24",
    "139.130.4.0/24",
    "139.175.252.0/24",
    "139.192.0.0/24",
    "140.205.50.0/24",
    "142.250.0.0/24",
    "151.99.125.0/24",
    "151.232.0.0/24",
    "164.124.101.0/24",
    "166.111.8.0/24",
    "168.95.1.0/24",
    "171.208.4.0/24",
    "172.217.14.0/24",
    "177.92.0.0/24",
    "180.76.76.0/24",
    "180.101.0.0/24",
    "180.101.172.0/24",
    "180.102.0.0/24",
    "180.103.0.0/24",
    "180.104.0.0/24",
    "180.105.0.0/24",
    "180.107.0.0/24",
    "180.108.0.0/24",
    "180.110.0.0/24",
    "180.111.0.0/24",
    "180.112.0.0/24",
    "180.113.0.0/24",
    "180.114.0.0/24",
    "180.180.216.0/24",
    "180.244.71.0/24",
    "181.115.0.0/24",
    "182.138.127.0/24",
    "182.254.116.0/24",
    "183.192.0.0/24",
    "183.192.64.0/24",
    "183.192.128.0/24",
    "183.192.192.0/24",
    "183.207.0.0/24",
    "183.207.64.0/24",
    "183.207.128.0/24",
    "183.207.192.0/24",
    "183.232.0.0/24",
    "183.232.64.0/24",
    "183.232.128.0/24",
    "183.232.192.0/24",
    "185.22.153.0/24",
    "185.93.180.0/24",
    "189.38.0.0/24",
    "190.104.0.0/24",
    "193.0.14.0/24",
    "194.190.245.0/24",
    "195.54.12.0/24",
    "196.200.160.0/24",
    "197.242.0.0/24",
    "198.101.242.0/24",
    "200.160.0.0/24",
    "201.217.0.0/24",
    "202.38.64.0/24",
    "202.86.0.0/24",
    "202.86.8.0/24",
    "202.96.0.0/24",
    "202.96.64.0/24",
    "202.96.69.0/24",
    "202.96.128.0/24",
    "202.96.134.0/24",
    "202.96.199.0/24",
    "202.96.209.0/24",
    "202.97.96.0/24",
    "202.97.211.0/24",
    "202.97.224.0/24",
    "202.98.5.0/24",
    "202.98.14.0/24",
    "202.98.96.0/24",
    "202.98.160.0/24",
    "202.98.161.0/24",
    "202.98.192.0/24",
    "202.98.198.0/24",
    "202.98.224.0/24",
    "202.99.96.0/24",
    "202.99.160.0/24",
    "202.99.192.0/24",
    "202.99.224.0/24",
    "202.100.0.0/24",
    "202.100.4.0/24",
    "202.100.72.0/24",
    "202.100.96.0/24",
    "202.100.128.0/24",
    "202.100.192.0/24",
    "202.101.98.0/24",
    "202.101.172.0/24",
    "202.101.224.0/24",
    "202.101.226.0/24",
    "202.102.3.0/24",
    "202.102.24.0/24",
    "202.102.128.0/24",
    "202.102.152.0/24",
    "202.102.192.0/24",
    "202.102.224.0/24",
    "202.102.227.0/24",
    "202.103.0.0/24",
    "202.103.24.0/24",
    "202.103.96.0/24",
    "202.103.224.0/24",
    "202.104.96.0/24",
    "202.105.0.0/24",
    "202.106.0.0/24",
    "202.106.64.0/24",
    "202.106.128.0/24",
    "202.106.192.0/24",
    "202.129.206.0/24",
    "202.138.96.0/24",
    "202.175.0.0/24",
    "203.50.2.0/24",
    "203.80.96.0/24",
    "203.98.7.0/24",
    "203.104.64.0/24",
    "203.113.172.0/24",
    "203.124.230.0/24",
    "203.144.207.0/24",
    "203.186.94.0/24",
    "203.226.206.0/24",
    "203.248.252.0/24",
    "208.67.222.0/24",
    "210.0.255.0/24",
    "210.21.0.0/24",
    "210.21.64.0/24",
    "210.21.128.0/24",
    "210.21.192.0/24",
    "210.21.196.0/24",
    "210.22.70.0/24",
    "210.82.0.0/24",
    "210.82.64.0/24",
    "210.82.128.0/24",
    "210.82.192.0/24",
    "210.185.0.0/24",
    "210.196.3.0/24",
    "210.209.120.0/24",
    "210.220.163.0/24",
    "211.136.0.0/24",
    "211.136.32.0/24",
    "211.136.64.0/24",
    "211.136.96.0/24",
    "211.136.128.0/24",
    "211.136.160.0/24",
    "211.136.192.0/24",
    "211.136.224.0/24",
    "211.137.0.0/24",
    "211.137.32.0/24",
    "211.137.64.0/24",
    "211.137.96.0/24",
    "211.137.128.0/24",
    "211.137.160.0/24",
    "211.137.192.0/24",
    "211.137.224.0/24",
    "211.138.0.0/24",
    "211.138.32.0/24",
    "211.138.64.0/24",
    "211.138.96.0/24",
    "211.138.128.0/24",
    "211.138.160.0/24",
    "211.138.180.0/24",
    "211.138.192.0/24",
    "211.138.224.0/24",
    "211.138.245.0/24",
    "211.139.0.0/24",
    "211.139.32.0/24",
    "211.139.64.0/24",
    "211.139.96.0/24",
    "211.139.128.0/24",
    "211.139.160.0/24",
    "211.139.192.0/24",
    "211.139.224.0/24",
    "217.169.20.0/24",
    "218.30.0.0/24",
    "218.30.118.0/24",
    "218.31.0.0/24",
    "218.75.0.0/24",
    "218.75.121.0/24",
    "218.76.0.0/24",
    "218.77.0.0/24",
    "218.104.0.0/24",
    "218.104.47.0/24",
    "218.104.64.0/24",
    "218.104.111.0/24",
    "218.104.128.0/24",
    "218.104.192.0/24",
    "218.201.96.0/24",
    "218.206.0.0/24",
    "219.72.0.0/24",
    "219.128.0.0/24",
    "219.137.0.0/24",
    "219.141.0.0/24",
    "219.141.136.0/24",
    "219.144.0.0/24",
    "219.148.0.0/24",
    "219.148.204.0/24",
    "219.150.0.0/24",
    "219.152.0.0/24",
    "219.158.0.0/24",
    "220.162.0.0/24",
    "220.162.96.0/24",
    "220.165.0.0/24",
    "220.168.0.0/24",
    "220.170.0.0/24",
    "220.172.0.0/24",
    "220.175.0.0/24",
    "220.178.0.0/24",
    "220.181.0.0/24",
    "221.5.0.0/24",
    "221.5.64.0/24",
    "221.5.88.0/24",
    "221.5.128.0/24",
    "221.5.192.0/24",
    "221.7.0.0/24",
    "221.7.64.0/24",
    "221.7.92.0/24",
    "221.7.128.0/24",
    "221.7.192.0/24",
    "221.11.0.0/24",
    "221.11.1.0/24",
    "221.11.64.0/24",
    "221.11.128.0/24",
    "221.11.192.0/24",
    "221.130.33.0/24",
    "222.85.0.0/24",
    "222.85.64.0/24",
    "222.88.0.0/24",
    "222.160.0.0/24",
    "222.161.0.0/24",
    "222.168.0.0/24",
    "222.169.0.0/24",
    "222.172.0.0/24",
    "222.172.200.0/24",
    "222.175.0.0/24",
    "222.209.0.0/24",
    "222.216.0.0/24",
    "222.218.0.0/24",
    "222.221.0.0/24",
    "222.240.0.0/24",
    "222.246.0.0/24",
    "222.246.129.0/24",
    "222.247.0.0/24",
    "222.248.0.0/24",
    "223.5.5.0/24",
    "223.81.0.0/24",
    "223.81.64.0/24",
    "223.81.128.0/24",
    "223.81.192.0/24",
    "223.104.0.0/24",
    "223.104.64.0/24",
    "223.104.128.0/24",
    "223.104.192.0/24",
    "223.104.255.0/24",
]


def _load_ecs_subnets():
    # ECS 地域子网清单已内嵌，不需要任何外部文件
    return list(ECS_SUBNETS)


def resolve_domain_ips(domain, ecs_list):
    """全量解析一个域名在各线路的 IPv4，返回 IP 集合。"""
    ips, cnames = set(), set()
    targets = _final_targets(domain)
    names = {domain} | targets
    for name in names:
        for base in PLAIN_DOH:
            _collect_answers(_doh_answers(name, base), ips, cnames)

    def one(ecs):
        got, junk = set(), set()
        for name in names:
            _collect_answers(_doh_answers(name, GOOGLE_DOH, ecs), got, junk)
        return got

    if ecs_list:
        with ThreadPoolExecutor(max_workers=ECS_WORKERS) as ex:
            for got in ex.map(one, ecs_list):
                ips |= got
    return ips


# ===== 主程序模块 =====
# 程序主流程控制，协调各个模块完成IP采集、检测、排序和输出

def main():
    """
    主程序入口
    
    执行完整的IP采集、检测、排序和输出流程：
    1. 采集IP地址
    2. 快速筛选
    3. 地区识别
    4. 深度测试（高级模式）
    5. 结果输出
    
    Returns:
        None: 程序执行完成后退出
    """
    start_time = time.time()
    
    # 1. 预处理：删除旧文件
    # 清理之前运行生成的结果文件，避免结果累积
    delete_file_if_exists('IPlist.txt')
    delete_file_if_exists('Senflare.txt')
    if CONFIG["advanced_mode"]:
        delete_file_if_exists('IPlist-Pro.txt')
        delete_file_if_exists('Senflare-Pro.txt')
        delete_file_if_exists('Ranking.txt')
    logger.info("🗑️ 预处理完成，旧文件已清理")

    # 2. 采集IP地址
    # 从多个API源并发采集IP地址，获取大量候选IP
    logger.info("📥 ===== 采集IP地址 =====")
    all_ips = []
    successful_sources = 0
    failed_sources = 0
    
    # 解析 CONFIG["domains"] 里的三个域名（唯一 IP 来源）
    ecs_list = _load_ecs_subnets()
    logger.info(f"🌐 ECS 地域子网 {len(ecs_list)} 个，开始全量解析 {len(CONFIG['domains'])} 个域名")
    for domain in CONFIG["domains"]:
        try:
            logger.info(f"🔍 解析 {domain} ...")
            domain_ips = resolve_domain_ips(domain, ecs_list)
            all_ips.extend(sorted(domain_ips))
            successful_sources += 1
            logger.info(f"✅ {domain} 解析到 {len(domain_ips)} 个 IP")
        except Exception as e:
            failed_sources += 1
            logger.error(f"❌ {domain} 解析出错: {str(e)[:50]}")
    logger.info(f"📊 采集统计: 成功 {successful_sources} 个域名，失败 {failed_sources} 个域名")

    # 3. IP去重与排序
    # 对采集到的IP进行去重和排序，确保唯一性
    unique_ips = sorted(list(set(all_ips)), key=lambda x: [int(p) for p in x.split('.')])
    logger.info(f"🔢 去重后共 {len(unique_ips)} 个唯一IP地址")
    # 总量上限 100 个（定死）：不管以后加多少个域名，全部域名解出的 IP 合并去重后最多留 100 个
    if len(unique_ips) > 100:
        unique_ips = unique_ips[:100]
        logger.info("✂️ 已截断为 100 个（总量上限）")
    
    # 检查是否有IP需要检测
    if not unique_ips:
        logger.warning("⚠️ 没有采集到任何IP地址，程序结束")
        return

    # 4. 快速筛选
    # 使用TCP连接测试快速剔除明显不可用的IP，减少后续测试工作量
    logger.info("🔍 ===== 快速筛选 =====")
    filtered_ips = []
    for ip in unique_ips:
        is_good, delay = quick_filter_ip(ip)
        if is_good:
            filtered_ips.append(ip)
            logger.info(f"✅ 可用 {ip}（延迟 {delay}ms）")
        else:
            logger.info(f"❌ {ip} 被快速筛选剔除")
    
    logger.info(f"🔍 快速筛选完成，保留 {len(filtered_ips)} 个IP")
    
    if not filtered_ips:
        logger.warning("⚠️ 快速筛选后无可用IP，程序结束")
        return

    # 5. 立即保存基础文件（快速筛选完成后）
    # 保存基础版IP列表，供用户快速使用
    logger.info("📄 ===== 保存基础文件 =====")
    with open('IPlist.txt', 'w', encoding='utf-8') as f:
        for ip in filtered_ips:
            f.write(f"{ip}\n")
    logger.info(f"📄 已保存 {len(filtered_ips)} 个可用IP到 IPlist.txt")
    
    # 6. 立即进行地区识别与结果格式化（提前保存Senflare.txt）
    # 对快速筛选的IP进行地区识别，生成格式化结果
    logger.info("🌍 ===== 并发地区识别与结果格式化 =====")
    # 使用快速筛选的IP进行地区识别
    ip_delay_data = [(ip, 0, 0) for ip in filtered_ips]  # 使用快速筛选的IP，延迟设为0
    
    region_results = get_regions_concurrently(ip_delay_data)
    
    # 按地区分组
    region_groups = defaultdict(list)
    for ip, region_code, min_delay, avg_delay in region_results:
        country_name = get_country_name(region_code)
        region_groups[country_name].append((ip, region_code, min_delay, avg_delay))
    
    logger.info(f"🌍 地区分组完成，共 {len(region_groups)} 个地区")
    
    # 生成并保存最终结果
    result_ips = []
    for region in sorted(region_groups.keys()):
        # 同一地区内按延迟排序（更快的在前）
        sorted_ips = sorted(region_groups[region], key=lambda x: x[2])  # 按min_delay排序
        for idx, (ip, code, min_delay, avg_delay) in enumerate(sorted_ips, 1):
            result_ips.append(ip)
        logger.debug(f"地区 {region} 格式化完成，包含 {len(sorted_ips)} 个IP")
    
    result_ips = result_ips[:100]  # 基础版上限 100 条（定死）
    # 宣传语固定分配：第 N 个 IP 配第 N 句，更新时只换 IP、文字不动
    entry_by_ip = {ip: FIXED_NODE_NAMES[i] for i, ip in enumerate(result_ips)}
    result = [f"{ip}# {entry_by_ip[ip]}" for ip in result_ips]
    if result:
        # 立即保存基础文件
        with open('Senflare.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(result))
        logger.info(f"📄 已保存 {len(result)} 条格式化记录到 Senflare.txt")
    else:
        logger.warning("⚠️ 无有效记录可保存")

    # 7. 延迟排名前30%筛选（基于快速筛选结果）
    # 根据延迟性能筛选出前30%的IP，用于后续深度测试
    logger.info("🔍 ===== 延迟排名前30%筛选 =====")
    # 对快速筛选的IP进行延迟排名筛选，使用快速筛选的实际延迟数据
    quick_filter_results = []
    for ip in filtered_ips:
        # 重新获取快速筛选的延迟数据
        is_good, delay = quick_filter_ip(ip)
        if is_good:
            quick_filter_results.append((ip, delay, delay, 0))  # (ip, min_delay, avg_delay, stability)
    
    latency_filtered_ips = latency_filter_ips(quick_filter_results, CONFIG["latency_filter_percentage"])
    logger.info(f"🔍 延迟筛选完成，保留 {len(latency_filtered_ips)} 个IP")

    # 8. TCP Ping测试（只测试延迟，不测试带宽）
    # 对筛选后的IP进行精确的TCP延迟测试
    logger.info("🔍 ===== TCP Ping测试 =====")
    tcp_ping_ips = test_ips_concurrently([ip for ip, _, _, _ in latency_filtered_ips])

    # 9. 带宽测试（只对筛选后的IP进行带宽测试）
    # 对通过延迟筛选的IP进行HTTP带宽测试，评估网络性能
    logger.info("🔍 ===== 带宽测试 =====")
    # 进行带宽测试
    bandwidth_results = []
    for i, (ip, delay) in enumerate(tcp_ping_ips, 1):
        is_fast, bandwidth, latency = test_ip_bandwidth_only(ip, i, len(tcp_ping_ips))
        if is_fast:
            # 使用TCP Ping测试的延迟数据
            min_delay = delay
            avg_delay = delay
            stability = 100  # 默认稳定性
            score = calculate_score(min_delay, avg_delay, bandwidth, stability)
            bandwidth_results.append((ip, min_delay, avg_delay, bandwidth, latency, score))
    available_ips = bandwidth_results

    # 8. 保存高级文件（按评分排序）
    # 生成高级版IP列表和详细排名信息
    if available_ips:
        # 按评分排序（如果测试了带宽）
        if len(available_ips[0]) > 5:
            available_ips.sort(key=lambda x: x[5], reverse=True)  # 按评分排序
        logger.info(f"📊 按综合评分排序完成")
        
        # 保存高级文件（高级选项）
        # 保存优选IP列表
        with open('IPlist-Pro.txt', 'w', encoding='utf-8') as f:
            for ip, min_delay, avg_delay, bandwidth, latency, score in available_ips:
                f.write(f"{ip}\n")
        logger.info(f"📄 已保存 {len(available_ips)} 个优选IP到 IPlist-Pro.txt")
        
        # 保存详细排名信息
        with open('Ranking.txt', 'w', encoding='utf-8') as f:
            for i, (ip, min_delay, avg_delay, bandwidth, latency, score) in enumerate(available_ips, 1):
                f.write(f"📊 [{i}/{len(available_ips)}] {ip}（延迟 {min_delay}ms，带宽 {bandwidth:.2f}Mbps，评分 {score:.1f}）\n")
        logger.info(f"📄 已保存排名详情到 Ranking.txt")
        
        # 保存高级格式化文件（使用优选IP重新生成）
        # 对优选IP进行地区识别，生成高级版格式化结果
        logger.info("🌍 ===== 高级地区识别与结果格式化 =====")
        # 使用优选IP进行地区识别
        pro_ip_delay_data = [(ip, 0, 0) for ip, _, _, _, _, _ in available_ips]
        pro_region_results = get_regions_concurrently(pro_ip_delay_data)
        
        # 按地区分组
        pro_region_groups = defaultdict(list)
        for ip, region_code, min_delay, avg_delay in pro_region_results:
            country_name = get_country_name(region_code)
            pro_region_groups[country_name].append((ip, region_code, min_delay, avg_delay))
        
        logger.info(f"🌍 高级地区分组完成，共 {len(pro_region_groups)} 个地区")
        
        # 生成高级格式化结果（同一个 IP 沿用基础版那句宣传语）
        pro_result_ips = []
        for region in sorted(pro_region_groups.keys()):
            # 同一地区内按延迟排序（更快的在前）
            sorted_ips = sorted(pro_region_groups[region], key=lambda x: x[2])  # 按min_delay排序
            for idx, (ip, code, min_delay, avg_delay) in enumerate(sorted_ips, 1):
                pro_result_ips.append(ip)
            logger.debug(f"高级地区 {region} 格式化完成，包含 {len(sorted_ips)} 个IP")
        
        pro_result_ips = pro_result_ips[:100]  # 高级版上限 100 条（定死）
        pro_result = [f"{ip}# {entry_by_ip.get(ip, FIXED_NODE_NAMES[i])}" for i, ip in enumerate(pro_result_ips)]
        if pro_result:
            with open('Senflare-Pro.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(pro_result))
            logger.info(f"📄 已保存 {len(pro_result)} 条高级格式化记录到 Senflare-Pro.txt")
        else:
            logger.warning("⚠️ 高级版无有效记录可保存")
    else:
        logger.warning("⚠️ 高级版无有效记录可保存")

    # 9. 保存缓存并显示统计信息
    # 保存地区缓存，显示运行统计信息
    save_region_cache()
    
    # 显示总耗时
    run_time = round(time.time() - start_time, 2)
    logger.info(f"⏱️ 总耗时: {run_time}秒")
    logger.info(f"📊 缓存统计: 总计 {len(region_cache)} 个")
    logger.info("🏁 ===== 程序完成 =====")

# ===== 程序入口 =====
# 程序启动入口，初始化缓存并执行主程序

if __name__ == "__main__":
    """
    程序启动入口
    
    初始化缓存系统，执行主程序流程，处理异常情况。
    支持用户中断和异常处理。
    """
    # 程序启动日志
    logger.info("🚀 ===== 开始IP处理程序 =====")
    
    # 初始化缓存系统
    load_region_cache()
    
    # 清理过期缓存条目
    clean_expired_cache()
    
    # 执行主程序流程
    try:
        main()
    except KeyboardInterrupt:
        logger.info("⏹️ 程序被用户中断")
    except Exception as e:
        logger.error(f"❌ 程序运行出错: {str(e)}")
