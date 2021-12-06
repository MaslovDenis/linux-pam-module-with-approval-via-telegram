import base64
import argparse


parser = argparse.ArgumentParser()

parser.add_argument('--otp-secret', '-s',
                    required=True,
                    help='OTP secret')
args = parser.parse_args()

print(base64.b64encode(args.otp_secret.encode()).decode("latin-1"))
