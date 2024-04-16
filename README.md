# Json_checker
Function that will check if file contain json that is defined as AWS::IAM::Role Policy and will return False if Resource field contains a single asterisk 

## Before running
You need:
- Python3, git and pip installed
- File with json that you want to check

## How to run
```
git clone https://github.com/mhytrek/Json_checker.git
cd Json_checker/json_parser
pip install -r requirements.txt
python json_checker.py <Path_to_file>
```

## Example of file
```
{
    "PolicyName": "root",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "IamListAccess",
                "Effect": "Allow",
                "Action": [
                    "iam:ListRoles",
                    "iam:ListUsers"
                ],
                "Resource": "*"
            }
        ]
    }
}

```


