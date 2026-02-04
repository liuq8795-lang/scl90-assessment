# SCL-90 心理健康测评系统部署指南

## 方案：Render 部署（免费，适合长期运行）

### 步骤 1：上传代码到 GitHub

1. 访问 https://github.com 并登录
2. 点击右上角 + 号 → New repository
3. Repository name 填写：`scl90-assessment`
4. 选择 Public → Create repository
5. 按照页面提示上传代码：
   ```
   git remote add origin https://github.com/你的用户名/scl90-assessment.git
   git branch -M main
   git push -u origin main
   ```

### 步骤 2：部署到 Render

1. 访问 https://render.com 并用 GitHub 登录
2. 点击 New → Web Service
3. Connect 你的 scl90-assessment 仓库
4. 配置：
   - Name: scl90
   - Build Command: `npm install`
   - Start Command: `node server.js`
   - Environment Variables: 添加 `PORT` = `3000`
5. 点击 Create Web Service

6. 部署完成后，访问提供的 URL 即可！

---

## 快速方案：ngrok 临时分享（立即可用）

```bash
# 安装 ngrok
brew install ngrok  # Mac
# 或从 https://ngrok.com 下载

# 启动服务
cd /Users/pikaqiu/Desktop/scl90-project
npm start

# 新开终端
ngrok http 3000
```

然后分享显示的 HTTPS 链接给别人。

---

## 管理后台

- URL: 你的域名/admin.html
- 管理员账号需要手动创建
- 创建方法：在服务器上运行
  ```bash
  node -e "
  const sqlite3 = require('sqlite3').verbose();
  const bcrypt = require('bcryptjs');
  const db = new sqlite3.Database('./scl90.db');
  bcrypt.hash('admin123', 10, (err, hash) => {
    db.run('INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, 1)', 
      ['admin', hash], 
      function(err) {
        if (err) console.log('可能已存在');
        else console.log('创建成功: admin / admin123');
        db.close();
      }
    );
  });
  "
  ```

---

## 文件结构

```
scl90-project/
├── server.js          # 后端服务
├── package.json        # 项目配置
├── public/
│   ├── index.html      # 用户测评页面
│   ├── admin.html      # 管理后台
│   └── admin-login.html # 管理员登录
└── scl90.db            # SQLite 数据库（自动生成）
```
