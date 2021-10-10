# Bugscanner Go

This tool is dedicated to [DARKTUNNEL.NET](https://www.darktunnel.net), please support us if you find this tool useful.


Install
-------

	go get -v github.com/aztecrabbit/bugscanner-go


#### Set go bin to PATH

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

*Another subcommand for scanning will be updated soon*


Updating
--------

	go get -v -u github.com/aztecrabbit/bugscanner-go
