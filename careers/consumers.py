"""
WebSocket consumers for real-time career page updates.
"""

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from django.utils import timezone

logger = logging.getLogger(__name__)


class CareersLiveUpdateConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time updates on browse pages.

    Broadcasts:
    - job_created: When new job is published
    - job_updated: When job details change
    - job_deleted: When job is unpublished/deleted
    - company_created: When new company registers
    - company_updated: When company profile changes
    - project_created: When new project/service is listed
    - project_updated: When project changes
    """

    JOBS_GROUP = 'careers_jobs_live'
    COMPANIES_GROUP = 'careers_companies_live'
    PROJECTS_GROUP = 'careers_projects_live'

    async def connect(self):
        """Handle WebSocket connection."""
        # Extract channel type from query params
        query_string = self.scope.get('query_string', b'').decode()
        params = dict(qc.split('=') for qc in query_string.split('&') if '=' in qc)

        self.channel_type = params.get('channel', 'jobs')  # jobs, companies, or projects

        # Join appropriate group
        if self.channel_type == 'jobs':
            self.group_name = self.JOBS_GROUP
        elif self.channel_type == 'companies':
            self.group_name = self.COMPANIES_GROUP
        elif self.channel_type == 'projects':
            self.group_name = self.PROJECTS_GROUP
        else:
            await self.close(code=4000)
            return

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

        # Send connection confirmation
        await self.send_json({
            'type': 'connection_established',
            'channel': self.channel_type,
            'timestamp': timezone.now().isoformat(),
        })

        logger.info(f"Client connected to {self.channel_type} live updates")

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

    async def receive(self, text_data=None, bytes_data=None):
        """Handle incoming messages (filters, ping)."""
        if not text_data:
            return

        try:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'ping':
                await self.send_json({'type': 'pong'})
            elif message_type == 'update_filters':
                # Client is updating their filter criteria
                # Store in connection state for personalized updates
                self.filters = data.get('filters', {})
                await self.send_json({
                    'type': 'filters_updated',
                    'filters': self.filters
                })

        except json.JSONDecodeError:
            await self.send_json({
                'type': 'error',
                'message': 'Invalid JSON'
            })

    # ===== Event Handlers =====

    async def job_created(self, event):
        """Handle new job creation event."""
        await self.send_json({
            'type': 'job_created',
            'job': event['job'],
            'timestamp': event.get('timestamp', timezone.now().isoformat()),
        })

    async def job_updated(self, event):
        """Handle job update event."""
        await self.send_json({
            'type': 'job_updated',
            'job': event['job'],
            'timestamp': event.get('timestamp', timezone.now().isoformat()),
        })

    async def job_deleted(self, event):
        """Handle job deletion event."""
        await self.send_json({
            'type': 'job_deleted',
            'job_id': event['job_id'],
            'timestamp': event.get('timestamp', timezone.now().isoformat()),
        })

    async def company_created(self, event):
        """Handle new company event."""
        await self.send_json({
            'type': 'company_created',
            'company': event['company'],
            'timestamp': event.get('timestamp', timezone.now().isoformat()),
        })

    async def company_updated(self, event):
        """Handle company update event."""
        await self.send_json({
            'type': 'company_updated',
            'company': event['company'],
            'timestamp': event.get('timestamp', timezone.now().isoformat()),
        })

    async def project_created(self, event):
        """Handle new project/service event."""
        await self.send_json({
            'type': 'project_created',
            'project': event['project'],
            'timestamp': event.get('timestamp', timezone.now().isoformat()),
        })

    async def project_updated(self, event):
        """Handle project update event."""
        await self.send_json({
            'type': 'project_updated',
            'project': event['project'],
            'timestamp': event.get('timestamp', timezone.now().isoformat()),
        })

    # ===== Helper Methods =====

    async def send_json(self, content):
        """Send JSON data to client."""
        await self.send(text_data=json.dumps(content))


# ===== Helper Functions for Broadcasting =====

def broadcast_job_created(job_data):
    """Broadcast job creation to all connected clients."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        CareersLiveUpdateConsumer.JOBS_GROUP,
        {
            'type': 'job_created',
            'job': job_data,
            'timestamp': timezone.now().isoformat(),
        }
    )


def broadcast_job_updated(job_data):
    """Broadcast job update to all connected clients."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        CareersLiveUpdateConsumer.JOBS_GROUP,
        {
            'type': 'job_updated',
            'job': job_data,
            'timestamp': timezone.now().isoformat(),
        }
    )


def broadcast_job_deleted(job_id):
    """Broadcast job deletion to all connected clients."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        CareersLiveUpdateConsumer.JOBS_GROUP,
        {
            'type': 'job_deleted',
            'job_id': job_id,
            'timestamp': timezone.now().isoformat(),
        }
    )


def broadcast_company_created(company_data):
    """Broadcast company creation to all connected clients."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        CareersLiveUpdateConsumer.COMPANIES_GROUP,
        {
            'type': 'company_created',
            'company': company_data,
            'timestamp': timezone.now().isoformat(),
        }
    )


def broadcast_company_updated(company_data):
    """Broadcast company update to all connected clients."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        CareersLiveUpdateConsumer.COMPANIES_GROUP,
        {
            'type': 'company_updated',
            'company': company_data,
            'timestamp': timezone.now().isoformat(),
        }
    )


def broadcast_project_created(project_data):
    """Broadcast project creation to all connected clients."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        CareersLiveUpdateConsumer.PROJECTS_GROUP,
        {
            'type': 'project_created',
            'project': project_data,
            'timestamp': timezone.now().isoformat(),
        }
    )


def broadcast_project_updated(project_data):
    """Broadcast project update to all connected clients."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        CareersLiveUpdateConsumer.PROJECTS_GROUP,
        {
            'type': 'project_updated',
            'project': project_data,
            'timestamp': timezone.now().isoformat(),
        }
    )
