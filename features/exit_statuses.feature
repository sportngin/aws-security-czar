Feature: exit statuses

  In order to specify expected exit statuses
  As a developer using Cucumber
  I want to use the "the exit status should be" step

  Scenario: exit status of 0
    When I run `ec2-security-czar`
    Then the exit status should be 0
