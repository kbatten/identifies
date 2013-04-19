#
# Cookbook Name:: identifies
# Recipe:: default

include_recipe "apt"

include_recipe "ntp"
include_recipe "fail2ban"

include_recipe "nginx"
include_recipe "python"
include_recipe "gunicorn"
include_recipe "supervisor"


# setup user and group
group node[:identifies][:group]

user node[:identifies][:user] do
  group node[:identifies][:group]
  system true
  shell "/bin/bash"
end


# nginx setup
nginx_site "000-default" do
  enable false
  notifies :restart, 'service[nginx]'
end

# setup identifi.es
# openssl rsa -in ssl.key -out /etc/nginx/conf/ssl.key
# cp ssl.crt /etc/nginx/conf/ssl-unified.crt
# echo >> /etc/nginx/conf/ssl-unified.crt
# curl https://www.startssl.com/certs/sub.class1.server.ca.pem https://www.startssl.com/certs/ca.pem >> /etc/nginx/conf/ssl-unified.crt
remote_directory "/var/ssl" do
  source "ssl"
  # seems like there should be a better way
  files_owner node['nginx']['user']
  files_group node['nginx']['group']
  files_mode 0400
  owner node['nginx']['user']
  owner node['nginx']['group']
  mode 0500
end

# create identifi.es config
template "#{node[:nginx][:dir]}/sites-available/#{node[:identifies][:servername]}.conf" do
  source "nginx.conf.erb"
  mode 0644
  notifies :reload, 'service[nginx]'
end

remote_directory "/var/www/#{node[:identifies][:servername]}" do
  source "www"
  files_owner node[:identifies][:user]
  files_group node[:identifies][:group]
  files_mode 0644
  owner node[:identifies][:user]
  group node[:identifies][:group]
  mode 0755
end

# enable site
nginx_site "#{node[:identifies][:servername]}.conf" do
  enable true
  notifies :restart, 'service[nginx]'
end


# gunicorn setup
# create a config with the default values
gunicorn_config "/etc/gunicorn/#{node[:identifies][:servername]}.py" do
  listen "127.0.0.1:8000"
  action :create
end


# flask setup
python_pip "flask" do
  action :install
end

# pycrypto setup
python_pip "pycrypto" do
  action :install
end


# supervisor setup, start the actual webapp
supervisor_service "gunicorn_app_app" do
  command "gunicorn app:app"
  directory "/var/www/#{node[:identifies][:servername]}/app"
  user node[:identifies][:user]
  autostart true
  autorestart true
  action [:enable, :start]
end
