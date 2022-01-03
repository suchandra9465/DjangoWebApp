
from __future__ import unicode_literals
from django.contrib import admin
from .models import Large,JobLog

# Register your models here.
admin.site.register(Large)
admin.site.register(JobLog)

# from __future__ import unicode_literals
# import logging

# from django.utils.html import format_html

# # from .models import StatusLog

# DJANGO_DB_LOGGER_ADMIN_LIST_PER_PAGE =10
# class StatusLogAdmin(admin.ModelAdmin):
#     list_display = ('colored_msg', 'traceback','ip_format')
#     list_display_links = ('colored_msg', )
#     list_filter = ('level', )
#     list_per_page = DJANGO_DB_LOGGER_ADMIN_LIST_PER_PAGE

#     def colored_msg(self, instance):
#         if instance.level in [logging.NOTSET, logging.INFO]:
#             color = 'green'
#         elif instance.level in [logging.WARNING, logging.DEBUG]:
#             color = 'orange'
#         else:
#             color = 'red'
#         return format_html('<span style="color: {color};">{msg}</span>', color=color, msg=instance.msg)
#     colored_msg.short_description = 'Message'

#     def traceback(self, instance):
#         return format_html('<pre><code>{content}</code></pre>', content=instance.trace if instance.trace else '')

#     def ip_format(self, ip):
#         return format_html('<pre><code>{content}</code></pre>', content=ip)
#     ip_format.short_description = 'Ip'
    

# admin.site.register(StatusLog, StatusLogAdmin)