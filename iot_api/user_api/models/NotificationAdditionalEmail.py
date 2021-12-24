from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email.utils
import smtplib
from flask.templating import render_template
from sqlalchemy import Column, BigInteger, Boolean, DateTime, String
from sqlalchemy.sql.schema import ForeignKey
from iot_api import config
from iot_api.user_api import db

class NotificationAdditionalEmail(db.Model):
    id = Column(BigInteger, primary_key=True)
    email = Column(String(120), nullable=False)
    token = Column(String(500), nullable=False)
    creation_date = Column(DateTime(timezone=False), nullable=False)
    active = Column(Boolean, nullable=False, default=False)
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), nullable=False)

    def delete(self):
        db.session.delete(self)

    def save(self):
        db.session.add(self)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'active': self.active
        }

    def update(self):
        db.session.commit()

    @classmethod 
    def send_emails(cls,app,alert_type,emails):
        if len(emails) > 0:
            with app.app_context():
                msg = MIMEMultipart('alternative')
                msg['Subject'] = f"New {config.BRAND_NAME} Notification"
                msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
                part = MIMEText(
                    render_template(
                        'notification.html',
                        brand_name=config.BRAND_NAME,
                        full_url=config.BRAND_URL,
                        alert_type=alert_type.name
                        ), 'html'
                    )
                msg.attach(part)
                server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                #server.set_debuglevel(1)
                server.ehlo()
                server.starttls()
                #stmplib docs recommend calling ehlo() before & after starttls()
                server.ehlo()
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)

                for email_user in emails:
                    try:
                        msg['To'] = email_user
                        server.sendmail(config.SMTP_SENDER,email_user, msg.as_string())
                    except Exception as exc:
                        server.close()
                        print(exc)
                server.close()

    @classmethod
    def add_not_repeated(cls,user,emails):
        if user.email and not user.email in emails:
            emails.append(user.email)
            additional = cls.find(user_id = user.id)
            for item in additional:
                if item.active and not item.email in emails:
                    emails.append(item.email)
    
    @classmethod
    def find(cls, user_id):
        return cls.query.filter(cls.user_id == user_id).all()

    @classmethod
    def find_one_by_token(cls, token):
        return cls.query.filter(cls.token == token).first()
