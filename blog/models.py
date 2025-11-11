from django.db import models
from wagtail.models import Page
from wagtail.fields import RichTextField
from wagtail.admin.panels import FieldPanel, MultiFieldPanel
from django.db import models
from modelcluster.tags import ClusterTaggableManager
from modelcluster.fields import ParentalKey

from django.utils.translation import gettext_lazy as _
from wagtail.fields import StreamField
from wagtail import blocks
from wagtail.images.blocks import ImageBlock

# Create your models here.

from wagtail import blocks

class RichTextCellBlock(blocks.RichTextBlock):
    pass

class TableRowBlock(blocks.StructBlock):
    cells = blocks.ListBlock(RichTextCellBlock())

class CustomTableBlock(blocks.StructBlock):
    header = blocks.ListBlock(blocks.CharBlock())
    rows = blocks.ListBlock(TableRowBlock())

class QuoteBlock(blocks.StructBlock):
    quote = blocks.BlockQuoteBlock(required=True, help_text="Texte de la citation")
    author = blocks.RichTextBlock(required=False, help_text="Auteur de la citation")
    source = blocks.RichTextBlock(required=False, help_text="Source de la citation")

    class Meta:
        icon = "openquote"

class BlogPostPage(Page):
    template = "blog/blog-detail1.html"

    STATUS_CHOICES = [
        ('draft', 'Brouillon'),
        ('scheduled', 'Planifié'),
        ('finished', 'Terminé'),
        ('published', 'Publié'),
    ]
    body = StreamField([
        ('heading', blocks.RichTextBlock(form_classname="title")),
        ('heading2', blocks.RichTextBlock(form_classname="title2")),
        ('heading3', blocks.RichTextBlock(form_classname="title3")),
        ('heading4', blocks.RichTextBlock(form_classname="title4")),
        ('heading5', blocks.RichTextBlock(form_classname="title5")),
        ('heading6', blocks.RichTextBlock(form_classname="title6")),
        ('ordered_list', blocks.ListBlock(blocks.RichTextBlock(), icon="list-ol")),
        ('unordered_list', blocks.ListBlock(blocks.RichTextBlock(), icon="list-ul")),
        ('paragraph', blocks.RichTextBlock()),
        ('image', ImageBlock()),
        ('quote', QuoteBlock()),
        ('table', CustomTableBlock()),
    ], null=True, blank=True)
    excerpt = models.TextField(max_length=300, blank=True)
    featured_image = models.ForeignKey(
        'wagtailimages.Image',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='+',
        help_text="Image principale"
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='draft')
    meta_title = models.CharField(max_length=200, blank=True)
    meta_description = models.TextField(blank=True)
    publishing_date = models.DateTimeField(null=True, blank=True)
    tags = ClusterTaggableManager(through='BlogPostTag', blank=True)

    content_panels = Page.content_panels + [
        FieldPanel("body"),
        FieldPanel("excerpt"),
        FieldPanel("featured_image"),
        FieldPanel("status"),
        FieldPanel("publishing_date"),
        FieldPanel("tags"),
    ]

    promote_panels = Page.promote_panels + [
        MultiFieldPanel([
            FieldPanel("meta_title"),
            FieldPanel("meta_description"),
        ], heading="SEO"),
    ]

class CategoryPage(Page):
    description = models.TextField(blank=True)
    
    content_panels = Page.content_panels + [
        FieldPanel("description"),
    ]

    parent_page_types = ['blog.BlogIndexPage']
    subpage_types = ['blog.CategoryPage', 'blog.BlogPostPage']


class BlogIndexPage(Page):
    intro = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        FieldPanel("intro"),
    ]

    # parent_page_types = ['wagtailcore.Page']

    subpage_types = ['blog.BlogPostPage', 'blog.CategoryPage']

    template = "blog/blog-default.html"

    def get_context(self, request):
        context = super().get_context(request)
        context['posts'] = BlogPostPage.objects.live().order_by('-first_published_at')
        return context


class Comment(models.Model):
    post = models.ForeignKey(
        'blog.BlogPostPage',
        related_name='comments',
        on_delete=models.CASCADE
    )
    author_name = models.CharField(max_length=120, default='', blank=True)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    parent = models.ForeignKey(
        'self',
        null=True, blank=True,
        related_name='replies',
        on_delete=models.CASCADE
    )

    def __str__(self):
        return f"{self.author_name} - {self.post.title}"


from modelcluster.fields import ParentalKey
from modelcluster.tags import ClusterTaggableManager
from taggit.models import TaggedItemBase

class BlogPostTag(TaggedItemBase):
    content_object = ParentalKey(
        'BlogPostPage',
        related_name='tagged_items',
        on_delete=models.CASCADE
    )

from auditlog.registry import auditlog

auditlog.register(BlogPostPage)
auditlog.register(Comment)
auditlog.register(CategoryPage)