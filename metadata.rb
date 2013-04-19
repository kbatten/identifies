name             "identifies"
maintainer       "keith batten"
maintainer_email "kbatten@gmail.com"
license          "MIT"
description      "Installs/Configures identifies"
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version          "0.2.0"

depends "apt"
depends "nginx"
depends "fail2ban"
depends "ntp"
depends "python"
depends "gunicorn"
depends "supervisor"
