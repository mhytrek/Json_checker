import unittest
import json_checker

class TestJson_checker(unittest.TestCase):

    def test_pars_json(self):
        data_1 = json_checker.pars_json("test_files/test")
        data_2 = json_checker.pars_json("test_files/test_2")
        data_3 = json_checker.pars_json("test_files/test_3")
        data_4 = json_checker.pars_json("test_files/test_4")

        expected_1 = {'PolicyName': 'root', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Sid': 'IamListAccess', 'Effect': 'Allow', 'Action': ['iam:ListRoles', 'iam:ListUsers'], 'Resource': '*'}]}}

        self.assertEqual(data_1, expected_1)
        self.assertEqual(data_2, -1)
        self.assertEqual(data_3, expected_1)
        self.assertEqual(data_4, -1)


    def test_check_version(self):
        data_1 = json_checker.check_version("2024-9-31")
        data_2 = json_checker.check_version("2019-10-10")
        data_3 = json_checker.check_version("2025-10-25")
        data_4 = json_checker.check_version("2020")

        self.assertFalse(data_1)
        self.assertTrue(data_2)
        self.assertFalse(data_3)
        self.assertFalse(data_4)


    def test_check_statement(self):
        data_1 = json_checker.check_statement({'Sid': 'IamListAccess', 'Effect': 'Allow', 'Action': ['iam:ListRoles', 'iam:ListUsers'], 'Resource': '*'})
        data_2 = json_checker.check_statement({'Effect': 'D', 'Action': ['iam:ListRoles', 'iam:ListUsers'], 'Resource': 'arn:aws:s3:::confidential-data'})
        data_3 = json_checker.check_statement({'Sid': 'IamListAccess', 'Effect': 'Allow', 'Action': ['iam:ListRoles', 'iam:ListUsers'], 'Resource': 'arn:aws:s3:::confidential-data'})
        data_4 = json_checker.check_statement({'Effect': 'Deny', 'Action': [], 'Resource': 'arn:aws:s3:::confidential-data'})

        self.assertFalse(data_1)
        self.assertFalse(data_2)
        self.assertTrue(data_3)
        self.assertFalse(data_4)


    def test_check_elements(self):
        data_1 = json_checker.check_elements({'Statement': [{'Sid': 'IamListAccess', 'Effect': 'Allow', 'Action': ['iam:ListRoles', 'iam:ListUsers'], 'Resource': 'arn:aws:s3:::confidential-data'}]})
        data_2 = json_checker.check_elements({'Version': '2012-10-17', 'Stat': [{'Sid': 'IamListAccess', 'Effect': 'Allow', 'Action': ['iam:ListRoles', 'iam:ListUsers'], 'Resource': 'arn:aws:s3:::confidential-data'}]})
        data_3 = json_checker.check_elements({'Version': '2030-10-17', 'Statement': [{'Sid': 'IamListAccess', 'Effect': 'Allow', 'Action': ['iam:ListRoles', 'iam:ListUsers'], 'Resource': 'arn:aws:s3:::confidential-data'}]})
        data_4 = json_checker.check_elements({'Version': '2010-10-17', 'Statement': [{'Sid': 'IamListAccess', 'Effect': 'Allow', 'Action': ['iam:ListRoles', 'iam:ListUsers'],'Resource': '*'}]})
        data_5 = json_checker.check_elements({'Version': '2010-10-17', 'Statement': [{'Sid': 'IamListAccess', 'Effect': 'Allow', 'Action': ['iam:ListRoles', 'iam:ListUsers'],'Resource': 'arn:aws:s3:::confidential-data'}]})

        self.assertFalse(data_1)
        self.assertFalse(data_2)
        self.assertFalse(data_3)
        self.assertFalse(data_4)
        self.assertTrue(data_5)


    def test_check_reguirements(self):
        data_1 = json_checker.check_reguirements({'PolicyName': 'B!@ck', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Sid': 'IamListAccess', 'Effect': 'Allow', 'Action': ['iam:ListRoles', 'iam:ListUsers'], 'Resource': 'arn:aws:s3:::confidential-data'}]}})
        data_2= json_checker.check_reguirements({'PolicyName': 'Black', 'PolicyDocument': {
                                                                                            'Statement': [
                                                                                                {'Sid': 'IamListAccess',
                                                                                                 'Effect': 'Allow',
                                                                                                 'Action': [
                                                                                                     'iam:ListRoles',
                                                                                                     'iam:ListUsers'],
                                                                                                 'Resource': 'arn:aws:s3:::confidential-data'}]}})
        name = "ABA" * 50
        data_3 = json_checker.check_reguirements({'PolicyName': name, 'PolicyDocument': {'Version': '2012-10-17',
                                                                                            'Statement': [
                                                                                                {'Sid': 'IamListAccess',
                                                                                                 'Effect': 'Allow',
                                                                                                 'Action': [
                                                                                                     'iam:ListRoles',
                                                                                                     'iam:ListUsers'],
                                                                                                 'Resource': 'arn:aws:s3:::confidential-data'}]}})

        data_4 = json_checker.check_reguirements({'PolicyName': '', 'PolicyDocument': {'Version': '2012-10-17',
                                                                                         'Statement': [
                                                                                             {'Sid': 'IamListAccess',
                                                                                              'Effect': 'Allow',
                                                                                              'Action': [
                                                                                                  'iam:ListRoles',
                                                                                                  'iam:ListUsers'],
                                                                                              'Resource': 'arn:aws:s3:::confidential-data'}]}})
        data_5 = json_checker.check_reguirements({'PolicyName': 'root', 'PolicyDocument': {'Version': '2012-10-17',
                                                                                         'Statement': [
                                                                                             {'Sid': 'IamListAccess',
                                                                                              'Effect': 'Allow',
                                                                                              'Action': [
                                                                                                  'iam:ListRoles',
                                                                                                  'iam:ListUsers'],
                                                                                              'Resource': '*'}]}})
        data_6 = json_checker.check_reguirements({'PolicyName': 'root', 'PolicyDocument': {'Version': '2012-10-17',
                                                                                           'Statement': [
                                                                                               {'Sid': 'IamListAccess',
                                                                                                'Effect': 'Allow',
                                                                                                'Action': [
                                                                                                    'iam:ListRoles',
                                                                                                    'iam:ListUsers'],
                                                                                                'Resource': 'arn:aws:s3:::confidential-data'}]}})

        self.assertFalse(data_1)
        self.assertFalse(data_2)
        self.assertFalse(data_3)
        self.assertFalse(data_4)
        self.assertFalse(data_5)
        self.assertTrue(data_6)

    def test_check_json(self):
        data_1 = json_checker.check_json("test_files/test")

        self.assertFalse(data_1)