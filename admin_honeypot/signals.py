from django.dispatch import Signal
from django.core.mail import mail_admins
from django.template.loader import render_to_string

honeypot = Signal()
# providing_args=['instance', 'request']

def notify_admins(sender, instance, request, **kwargs):
    subject = render_to_string('admin_honeypot/email_subject.txt', {'instance': instance})
    message = render_to_string('admin_honeypot/email_message.txt', {'instance': instance, 'request': request})
    mail_admins(subject, message)
