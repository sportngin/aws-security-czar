# AwsSecurityCzar

Manages changes to AWS EC2 Security Groups via YAML files.

## Installation

Add this line to your application's Gemfile:

    gem 'aws-security-czar'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install aws-security-czar

## Setup
#### Install gems:

```
bundle install
```

#### Add your aws credentials to the environment config:

```yml
# config/aws_keys.yml
---
staging:
  access_key: YOUR_ACCESS_KEY
  secret_key: YOUR_SECRET_KEY
production:
  access_key: YOUR_ACCESS_KEY
  secret_key: YOUR_SECRET_KEY

```

## Usage

#### Configure the rules:
Each file in `config/` should match up with the name of a security group. Enter the rules in the following format:

```yml
---
description: App Servers for Taco Service
vpc: <%= environment == "production" ? 'vpc-wsad' : 'vpc-asdf' %>
region: <%= environment == "production" ? 'us-east-1' : 'us-west-2' %>
inbound:
-
  :zone: Private Subnet # Optional description
  :protocol: :any # Leave Blank for all protocols
  :port_range: 443 # Leave Blank for all ports
  :ip_ranges:
  - 10.0.0.0/24
outbound: # Inbound and outbound rules are separate
-
  :zone: Private Subnet
  :protocol: :tcp
  :port_range: 443
  :ip_ranges:
  - 10.0.0.0/24
```


#### Update the rules on AWS:

**Note:** If no region is specified `us-east-1` is assumed.

```
aws-security-czar update [-r region_name] <environment_name>
```


## Contributing

1. Fork it ( https://github.com/[my-github-username]/aws-security-czar/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
