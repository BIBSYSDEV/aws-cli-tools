Setup
=====

Using pipenv
------------

Prepare tools:

`$ apt install python-pip`

`$ pip install --user pipenv`

Install requirements:

`$ pipenv install`

Run script:

`$ pipenv run python samlauth.py`

Simple
------
Install Python3

(Depends on OS/Distro)

Install requirements:

`pip3 install --upgrade boto3`

`pip3 install --upgrade bs4`

`pip3 install --upgrade ConfigParser`

Run script:

`python3 samlauth.py -h`

or

`./samlauth.py -h`

Usage
=====

'default' profile should be the AWS account you use on a daily basis. Use named profiles for other accounts.

Default profile
---------------
`samlauth.py -a NVAsandbox`

`aws sts get-caller-identity`

Named profile
-------------
`samlauth.py -a NVAsandbox -p nva-sandbox`

`aws sts get-caller-identity --profile nva-sandbox`
