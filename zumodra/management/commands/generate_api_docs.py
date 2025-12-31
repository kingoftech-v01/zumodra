"""
Management command to generate API documentation.
Creates OpenAPI/Swagger documentation from DRF viewsets.
"""

import json
import os
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings


class Command(BaseCommand):
    help = 'Generate API documentation in OpenAPI/Swagger format'

    def add_arguments(self, parser):
        parser.add_argument(
            '--output',
            type=str,
            default='api_docs',
            help='Output directory for documentation (default: api_docs)'
        )
        parser.add_argument(
            '--format',
            type=str,
            default='openapi',
            choices=['openapi', 'markdown', 'html'],
            help='Output format (default: openapi)'
        )
        parser.add_argument(
            '--title',
            type=str,
            default='Zumodra API',
            help='API title'
        )
        parser.add_argument(
            '--version',
            type=str,
            default='1.0.0',
            help='API version'
        )
        parser.add_argument(
            '--include-private',
            action='store_true',
            help='Include private/internal endpoints'
        )
        parser.add_argument(
            '--split-by-app',
            action='store_true',
            help='Split documentation by Django app'
        )

    def handle(self, *args, **options):
        output_dir = options['output']
        output_format = options['format']
        title = options['title']
        version = options['version']
        include_private = options.get('include_private', False)
        split_by_app = options.get('split_by_app', False)

        self.stdout.write(f"Generating API documentation...")
        self.stdout.write(f"  Format: {output_format}")
        self.stdout.write(f"  Output: {output_dir}/")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        try:
            if output_format == 'openapi':
                self._generate_openapi(
                    output_dir, title, version, include_private, split_by_app
                )
            elif output_format == 'markdown':
                self._generate_markdown(
                    output_dir, title, version, include_private, split_by_app
                )
            elif output_format == 'html':
                self._generate_html(
                    output_dir, title, version, include_private
                )

            self.stdout.write(self.style.SUCCESS(f"\nDocumentation generated in: {output_dir}/"))

        except Exception as e:
            raise CommandError(f"Failed to generate documentation: {e}")

    def _generate_openapi(self, output_dir, title, version, include_private, split_by_app):
        """Generate OpenAPI 3.0 specification."""
        try:
            from rest_framework.schemas.openapi import SchemaGenerator
        except ImportError:
            raise CommandError("Django REST Framework is required for OpenAPI generation")

        # Generate schema
        generator = SchemaGenerator(title=title)

        try:
            schema = generator.get_schema()
        except Exception:
            # Fall back to manual schema generation
            schema = self._build_manual_schema(title, version)

        # Update info section
        schema['info'] = {
            'title': title,
            'version': version,
            'description': 'Zumodra ATS/HR SaaS Platform API',
            'contact': {
                'name': 'API Support',
                'email': 'api@zumodra.com',
            },
            'license': {
                'name': 'Proprietary',
            },
        }

        # Add servers
        schema['servers'] = [
            {'url': 'https://api.zumodra.com/v1', 'description': 'Production'},
            {'url': 'https://staging-api.zumodra.com/v1', 'description': 'Staging'},
            {'url': 'http://localhost:8000/api/v1', 'description': 'Development'},
        ]

        # Add security schemes
        schema['components'] = schema.get('components', {})
        schema['components']['securitySchemes'] = {
            'bearerAuth': {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT',
            },
            'apiKey': {
                'type': 'apiKey',
                'in': 'header',
                'name': 'X-API-Key',
            },
        }
        schema['security'] = [{'bearerAuth': []}, {'apiKey': []}]

        # Write output
        output_file = os.path.join(output_dir, 'openapi.json')
        with open(output_file, 'w') as f:
            json.dump(schema, f, indent=2)

        self.stdout.write(f"  Created: {output_file}")

        # Also create YAML version
        try:
            import yaml
            yaml_file = os.path.join(output_dir, 'openapi.yaml')
            with open(yaml_file, 'w') as f:
                yaml.dump(schema, f, default_flow_style=False, sort_keys=False)
            self.stdout.write(f"  Created: {yaml_file}")
        except ImportError:
            pass

    def _build_manual_schema(self, title, version):
        """Build OpenAPI schema manually from URL patterns."""
        from django.urls import get_resolver

        schema = {
            'openapi': '3.0.3',
            'info': {'title': title, 'version': version},
            'paths': {},
        }

        # Get all URL patterns
        resolver = get_resolver()
        patterns = self._extract_patterns(resolver.url_patterns, prefix='')

        for pattern in patterns:
            if '/api/' in pattern['path']:
                schema['paths'][pattern['path']] = self._build_path_item(pattern)

        return schema

    def _extract_patterns(self, patterns, prefix=''):
        """Recursively extract URL patterns."""
        from django.urls import URLPattern, URLResolver

        results = []

        for pattern in patterns:
            path = prefix + str(pattern.pattern)

            if isinstance(pattern, URLPattern):
                results.append({
                    'path': '/' + path.replace('<', '{').replace('>', '}'),
                    'name': pattern.name,
                    'callback': pattern.callback,
                })
            elif isinstance(pattern, URLResolver):
                results.extend(self._extract_patterns(pattern.url_patterns, path))

        return results

    def _build_path_item(self, pattern):
        """Build OpenAPI path item from URL pattern."""
        path_item = {}
        callback = pattern.get('callback')

        if callback:
            # Determine HTTP methods from view
            methods = getattr(callback, 'actions', {})
            if not methods:
                # Default to common methods
                methods = {'get': 'list', 'post': 'create'}

            for method, action in methods.items():
                path_item[method] = {
                    'summary': f'{action.title()} {pattern["name"] or "resource"}',
                    'operationId': f'{method}_{pattern["name"] or "resource"}',
                    'tags': [self._get_tag_from_path(pattern['path'])],
                    'responses': {
                        '200': {'description': 'Successful response'},
                        '400': {'description': 'Bad request'},
                        '401': {'description': 'Unauthorized'},
                        '404': {'description': 'Not found'},
                    },
                }

        return path_item

    def _get_tag_from_path(self, path):
        """Extract tag/group name from path."""
        parts = path.strip('/').split('/')
        for part in parts:
            if part and part != 'api' and not part.startswith('{'):
                return part.replace('_', ' ').title()
        return 'General'

    def _generate_markdown(self, output_dir, title, version, include_private, split_by_app):
        """Generate Markdown documentation."""
        # First generate OpenAPI schema
        self._generate_openapi(output_dir, title, version, include_private, split_by_app)

        # Read the generated schema
        schema_file = os.path.join(output_dir, 'openapi.json')
        with open(schema_file, 'r') as f:
            schema = json.load(f)

        # Generate Markdown
        md_content = f"""# {title}

**Version:** {version}

{schema.get('info', {}).get('description', '')}

## Authentication

The API supports the following authentication methods:

- **Bearer Token (JWT)**: Include the token in the Authorization header
- **API Key**: Include your API key in the X-API-Key header

## Endpoints

"""
        # Group endpoints by tag
        endpoints_by_tag = {}
        for path, methods in schema.get('paths', {}).items():
            for method, details in methods.items():
                if isinstance(details, dict):
                    tags = details.get('tags', ['General'])
                    for tag in tags:
                        if tag not in endpoints_by_tag:
                            endpoints_by_tag[tag] = []
                        endpoints_by_tag[tag].append({
                            'path': path,
                            'method': method.upper(),
                            'summary': details.get('summary', ''),
                            'description': details.get('description', ''),
                        })

        for tag, endpoints in sorted(endpoints_by_tag.items()):
            md_content += f"\n### {tag}\n\n"
            md_content += "| Method | Endpoint | Description |\n"
            md_content += "|--------|----------|-------------|\n"

            for endpoint in endpoints:
                md_content += f"| `{endpoint['method']}` | `{endpoint['path']}` | {endpoint['summary']} |\n"

        # Write Markdown file
        md_file = os.path.join(output_dir, 'API.md')
        with open(md_file, 'w') as f:
            f.write(md_content)

        self.stdout.write(f"  Created: {md_file}")

    def _generate_html(self, output_dir, title, version, include_private):
        """Generate HTML documentation using Swagger UI."""
        # First generate OpenAPI schema
        self._generate_openapi(output_dir, title, version, include_private, False)

        # Generate HTML with embedded Swagger UI
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body {{
            margin: 0;
            padding: 0;
        }}
        .swagger-ui .topbar {{
            display: none;
        }}
        .header {{
            background: #1e40af;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
        }}
        .header p {{
            margin: 5px 0 0;
            opacity: 0.8;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <p>Version {version}</p>
    </div>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {{
            SwaggerUIBundle({{
                url: "openapi.json",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout",
                defaultModelsExpandDepth: 1,
                defaultModelExpandDepth: 1,
            }});
        }};
    </script>
</body>
</html>
"""

        html_file = os.path.join(output_dir, 'index.html')
        with open(html_file, 'w') as f:
            f.write(html_content)

        self.stdout.write(f"  Created: {html_file}")
        self.stdout.write(f"\n  Open {html_file} in a browser to view the documentation")
