# FlareGate

A lightweight, high-performance web dashboard to manage Cloudflare Tunnel hostnames and ingress rules. Built with **Go (Golang)** and **Tailwind CSS**, it simplifies the process of mapping public domains to local services without manually editing YAML files or using the slow Cloudflare Zero Trust dashboard.

## ✨ Features

- **Blazing Fast**: Written in Go using the [Gin](https://github.com/gin-gonic/gin) framework.
- **Single Binary**: Compiles into a single executable for easy deployment.
- **Beautiful UI**: Modern, responsive dashboard built with Tailwind CSS.
- **Magic Setup**: Simple setup wizard to verify your Cloudflare API token and select a tunnel.
- **Dashboard Management**:
  - **Add Hostnames**: Automatically creates DNS CNAME records and updates Tunnel Ingress rules in one click.
  - **Edit Services**: Quickly change the local service URL (e.g., changing port).
  - **Delete Hostnames**: Remove routes safely.
- **Persistent Storage**: Stores configuration in a local SQLite database (`data/tunnel_manager.db`).
- **Error Handling**: Graceful error handling with custom error pages.

## 🛠️ Prerequisites

- **Go 1.16+**: Required to build the application.
- **GCC**: Required for `go-sqlite3` driver (part of `build-essential` on Linux).
- **Cloudflare Account**: You need an active Cloudflare account and a Cloudflare Tunnel created (Managed Remotely).

## 🚀 Installation & Build

1.  **Clone the repository** (if applicable) or navigate to the project source.

2.  **Initialize Dependencies**:
    ```bash
    go mod tidy
    ```

3.  **Build the Binary**:
    ```bash
    go build -o flaregate
    ```

    This will create an executable file named `flaregate` in the current directory.

## ⚙️ Configuration

1.  **Environment Variables**:
    Copy the example environment file:
    ```bash
    cp .env.example .env
    ```

2.  **Edit `.env`**:
    Open `.env` and configure your admin credentials and port:
    ```ini
    PORT=8020
    SECRET_KEY=change_this_to_a_random_secret_string
    ADMIN_USERNAME=admin
    ADMIN_PASSWORD=password
    ```

    > **Note**: You do not put your Cloudflare Token here. You will enter that in the web UI.

## 🖥️ Usage

1.  **Run the Application**:
    ```bash
    ./flaregate
    ```
    *Note: Ensure the `templates/` and `static/` folders are in the same directory as the binary.*

2.  **Access the Dashboard**:
    Open your browser and navigate to:
    `http://localhost:8020`

3.  **First Time Setup**:
    - Log in with the `ADMIN_USERNAME` and `ADMIN_PASSWORD` you set in `.env`.
    - You will be greeted by the **Setup Wizard**.
    - Enter your **Cloudflare API Token**.
      - *Required Permissions*: `Account:Read`, `Zone:Read`, `DNS:Edit`, `Tunnel:Edit`.
    - Click **Verify**, select your desired Tunnel, and Click **Save & Continue**.

4.  **Manage Routes**:
    - Use the **Add New Hostname** button to map a subdomain (e.g., `app.example.com`) to a local service (e.g., `http://localhost:3000`).
    - The tool will automatically handle the DNS CNAME and Ingress configuration for you.

## 📂 Project Structure

```
├── data/               # SQLite database storage (created on first run)
├── static/             # Static assets (favicon, css, js)
├── templates/          # HTML templates (Go templates)
├── main.go             # Main application logic
├── go.mod              # Go module definition
├── .env                # Environment configuration
└── README.md           # This file
```

## ⚠️ Common Issues

- **"gcc: executable file not found"**: The SQLite driver requires CGO. Install `build-essential` on Ubuntu/Debian (`sudo apt install build-essential`) or MinGW on Windows.
- **"Port 8020 is already in use"**: The app will fail to start if the port is busy. Kill the process using the port (command provided in logs) or change `PORT` in `.env`.

---
*Built with ❤️ using Go and Cloudflare API*