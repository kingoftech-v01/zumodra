"""
WebSocket consumer for real-time public job updates.

Broadcasts new jobs and updates to connected map viewers for instant updates.

Channel Groups:
    - public_jobs_updates: Broadcast group for all job catalog events

Event Types:
    - job_created: New job published to catalog
    - job_updated: Existing job re-synced to catalog
    - job_removed: Job removed from catalog (closed/internal/deleted)

Usage:
    Connect to: ws://domain/ws/jobs/public/
    Client receives JSON messages with job data for real-time map marker updates.
"""

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async

logger = logging.getLogger(__name__)


class PublicJobsConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for public job catalog updates.

    Clients connect to receive real-time notifications when:
    - New jobs are published (job_created)
    - Existing jobs are updated (job_updated)
    - Jobs are removed/closed (job_removed)

    Used by map views to update markers in real-time without page refresh.

    Message Format (received by client):
        {
            "type": "job_created" | "job_updated" | "job_removed",
            "job": {
                "id": "uuid",
                "title": "...",
                "company_name": "...",
                "location": {"lat": 37.7749, "lng": -122.4194, "display": "..."},
                ...
            }
        }
    """

    async def connect(self):
        """
        Accept WebSocket connection and join public jobs broadcast group.

        All connected clients receive the same job update events.
        No authentication required (public data only).
        """
        # Join the public jobs broadcast group
        self.group_name = 'public_jobs_updates'

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()
        logger.info(f"Client connected to public jobs WebSocket (channel: {self.channel_name})")

    async def disconnect(self, close_code):
        """
        Leave broadcast group on disconnect.

        Args:
            close_code: WebSocket close code (1000 = normal closure)
        """
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
        logger.info(f"Client disconnected from public jobs WebSocket (code: {close_code})")

    async def receive(self, text_data):
        """
        Handle incoming messages from client.

        Clients can send ping messages to keep connection alive.

        Args:
            text_data: JSON string from client
        """
        try:
            data = json.loads(text_data)

            if data.get('type') == 'ping':
                # Respond to ping with pong (keep-alive)
                await self.send(text_data=json.dumps({
                    'type': 'pong',
                    'timestamp': data.get('timestamp')
                }))
                logger.debug(f"Responded to ping from {self.channel_name}")

        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON received from {self.channel_name}: {text_data}")

    async def job_created(self, event):
        """
        Send job created event to client.

        Triggered when a new job is published to public catalog.
        Clients should add a new marker to the map.

        Args:
            event: Event dict with 'job' key containing job data
        """
        await self.send(text_data=json.dumps({
            'type': 'job_created',
            'job': event['job']
        }))
        logger.debug(f"Broadcasted job_created for {event['job'].get('uuid', 'unknown')}")

    async def job_updated(self, event):
        """
        Send job updated event to client.

        Triggered when a job is re-synced to public catalog.
        Clients should update the existing marker.

        Args:
            event: Event dict with 'job' key containing updated job data
        """
        await self.send(text_data=json.dumps({
            'type': 'job_updated',
            'job': event['job']
        }))
        logger.debug(f"Broadcasted job_updated for {event['job'].get('uuid', 'unknown')}")

    async def job_removed(self, event):
        """
        Send job removed event to client.

        Triggered when a job is removed from public catalog.
        Clients should remove the marker from the map.

        Args:
            event: Event dict with 'job_uuid' key
        """
        await self.send(text_data=json.dumps({
            'type': 'job_removed',
            'job_uuid': event['job_uuid']
        }))
        logger.debug(f"Broadcasted job_removed for {event.get('job_uuid', 'unknown')}")
