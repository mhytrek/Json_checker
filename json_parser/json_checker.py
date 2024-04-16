import json
import re
import sys
from dateutil.parser import parse
from datetime import datetime

def pars_json(file):
    opened_file = open(file)
    lines = opened_file.read()
    opened_file.close()
    try:
        data = json.loads(lines)
    except:
        print("That is not AWS::IAM::Role Policy \n JSON data is not correct")
        return -1
    return data


def check_version(version):
    try:
        date_version = parse(version)
    except:
        print("That is not AWS::IAM::Role Policy \n Version is not correct")
        return False
    if version in ["2012-10-17", "2008-10-17"]:
        return True
    else:
        print("That is not AWS::IAM::Role Policy \n Version is not correct")
        return False


def check_statement(statement):
    sid = statement.get("Sid")
    effect = statement.get("Effect")
    action = statement.get("Action")
    resource = statement.get("Resource")
    condition = statement.get("Condition")
    if effect not in ["Allow", "Deny"]:
        print("That is not AWS::IAM::Role Policy \n Effect in Statement is not correct")
        return False
    elif len(action) <= 0:
        print("That is not AWS::IAM::Role Policy \n Action in Statement is not correct")
        return False
    elif resource == "*":
        print("Asterisk in Resource field")
        return False
    return True


def check_elements(document):
    version = document.get("Version")
    statements = document.get("Statement")
    if version is None:
        print("That is not AWS::IAM::Role Policy \n No Version")
        return False
    elif statements is None:
        print("That is not AWS::IAM::Role Policy \n No Statement")
        return False
    elif not check_version(version):
        return False
    for statement in statements:
        if not check_statement(statement):
            return False
    return True



def check_reguirements(data):
    name = data.get("PolicyName")
    if name is None or len(name) < 1 or len(name) > 128:
        print("That is not AWS::IAM::Role Policy \n Name doesn't exist or name has wrong length")
        return False
    name_span = re.search(r"[\w+=,.@-]+", name).span()
    if name_span[1] - name_span[0] < len(name):
        print("That is not AWS::IAM::Role Policy \n Name contains of not approved symbols")
        return False
    if not check_elements(data.get("PolicyDocument")):
        return False
    return True


def check_json():
    data = pars_json(sys.argv[1])
    if data == -1:
        return False
    return check_reguirements(data)

if __name__ == "__main__":
    print(check_json())


