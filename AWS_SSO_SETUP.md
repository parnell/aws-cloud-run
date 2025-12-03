# Using AWS SSO with aws-cloud-run

This project uses boto3, which automatically picks up AWS SSO credentials from your AWS configuration.

## Quick Start

1. **Login to AWS SSO:**
   ```bash
   aws sso login
   ```

2. **If you have multiple profiles**, specify which one to use:
   ```bash
   export AWS_PROFILE=your-profile-name
   ```

3. **Verify your credentials are working:**
   ```bash
   aws sts get-caller-identity
   ```

4. **Run your script:**
   ```bash
   python run_script_example.py
   ```

## How It Works

boto3 uses the default credential chain, which checks in this order:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. AWS credentials file (`~/.aws/credentials`)
3. AWS config file (`~/.aws/config`) - **This is where SSO profiles are stored**
4. IAM roles (if running on EC2/ECS/Lambda)

When you run `aws sso login`, it stores temporary credentials in `~/.aws/sso/cache/` and boto3 automatically uses them.

## Troubleshooting

**Error: Unable to locate credentials**
- Make sure you've run `aws sso login` recently (SSO sessions expire)
- Check your `~/.aws/config` file has the SSO profile configured
- Try: `export AWS_PROFILE=your-profile-name`

**Error: The SSO session associated with this profile has expired**
- Run `aws sso login` again to refresh your session

**Multiple profiles:**
- List profiles: `aws configure list-profiles`
- Use a specific profile: `export AWS_PROFILE=profile-name`
- Or specify in code (if needed): `boto3.Session(profile_name='profile-name')`

