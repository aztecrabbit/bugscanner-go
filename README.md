# Bugscanner Go

Install
-------

	go get -v github.com/aztecrabbit/bugscanner-go


#### Add go bin to PATH

**Bash**

	echo 'PATH="$PATH:$HOME/go/bin"' >> $HOME/.bashrc && source $HOME/.bashrc

**Zsh**

	echo 'PATH="$PATH:$HOME/go/bin"' >> $HOME/.zshrc && source $HOME/.zshrc


Usage
-----

	bugscanner-go --help


### Before Scanning

**1. Install subfinder (or any tool for finding subdomain)**

Visit subfinder repo if you want to install subfinder [here](https://github.com/projectdiscovery/subfinder#installation)


**2. Scan subdomain using subfinder and save it to file**

	subfinder -d example.com -o example.com.lst


### Scanning

#### Scan Server Name Indication

	bugscanner-go scan sni -f example.com.lst --threads 16 --timeout 8 --deep 3

#### Scan CDN SSL

	bugscanner-go scan cdn-ssl --cidr 127.0.0.1/32 --target example.com

Please execute like this to see more options

	bugscanner-go scan cdn-ssl --help

How to find cidr of cdn? Just googling `cdn-name cidr` e.g. `cloudflare cidr`, etc.

#### Note

*Another subcommand for scanning will be updated soon*


Updating
--------

	go get -v -u github.com/aztecrabbit/bugscanner-go


About
-----

This tool is dedicated to [DARKTUNNEL.NET](https://www.darktunnel.net), please support us if you find this tool useful.
