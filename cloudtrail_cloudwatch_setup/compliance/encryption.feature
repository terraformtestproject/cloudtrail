Feature: Check if s3 has encrypted
Scenario: Ensure all S3 buckets are encrypted
Given I have AWS S3 Bucket defined
Then encryption at rest must be enabled
