from django.db import models
from django.utils import timezone
from django.utils.text import slugify
from custom_account_u.models import CustomUser
from tinymce.models import HTMLField
from django.contrib import admin

from wagtail.models import Page
from wagtail.fields import RichTextField
from wagtail.admin.panels import FieldPanel, MultiFieldPanel, FieldRowPanel
from django.db import models
from django.utils.text import slugify
from django.utils import timezone
from modelcluster.tags import ClusterTaggableManager
from modelcluster.fields import ParentalKey

from django.utils.translation import gettext_lazy as _
from wagtail.fields import StreamField
from wagtail import blocks
from wagtail.images.blocks import ImageBlock
from wagtail.contrib.table_block.blocks import TableBlock

# Create your models here.

class BlogPost(models.Model):
    """
    Article de blog complet.
    """
    STATUS_CHOICES = [
        ('draft', 'Brouillon'),
        ('scheduled', 'Planifié'),
        ('finished', 'Terminé'),
        ('published', 'Publié'),
    ]

    title = models.CharField(max_length=200, help_text="Titre de l'article")
    slug = models.SlugField(max_length=200, unique=True, help_text="Slug unique pour l'URL")
    content_html = HTMLField()
    excerpt = models.TextField(max_length=300, blank=True, help_text="Résumé de l'article")
    author = models.ForeignKey(
        CustomUser, on_delete=models.PROTECT,
        help_text="Auteur de l'article"
    )
    category = models.ForeignKey(
        'Category',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        help_text="Catégorie de l'article (optionnel)"
    )
    tags = models.ManyToManyField(
        'Tag', blank=True, help_text="Tags associés à l'article"
    )
    featured_image = models.ImageField(upload_to='blog_images/', null=False, blank=False, help_text="Image principale")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='draft', help_text="Statut de publication")
    meta_title = models.CharField(max_length=200, blank=True, help_text="Titre SEO (optionnel)")
    meta_description = models.TextField(blank=True, help_text="Description SEO (optionnelle)")
    publishing_date = models.DateTimeField(null=True, blank=True, help_text="Date de publication planifiée")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Date de création")
    updated_at = models.DateTimeField(auto_now=True, help_text="Date de modification")

    def save(self, *args, **kwargs):
        # Générer le slug automatiquement si non renseigné
        if not self.slug:
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('blog:post_detail', args=[self.slug])
    
    @property
    def comment_count(self):
        return self.comments.filter(parent=None).count()

    def __str__(self):
        return self.title

    class Meta:
        ordering = ['-created_at']

# class Comment(models.Model):
#     """
#     Commentaire sur un article de blog, avec possibilité de répondre à un autre commentaire.
#     """
#     post = models.ForeignKey(
#         BlogPost, related_name='comments',
#         on_delete=models.CASCADE,
#         help_text="Article associé au commentaire"
#     )
#     author = models.ForeignKey(
#         CustomUser, on_delete=models.PROTECT,
#         help_text="Auteur du commentaire"
#     )
#     content = models.TextField(help_text="Contenu du commentaire")
#     created_at = models.DateTimeField(auto_now_add=True, help_text="Date de création")
#     parent = models.ForeignKey(
#         'self',
#         null=True, blank=True,
#         related_name='replies',
#         on_delete=models.CASCADE,
#         help_text="Commentaire parent si ce commentaire est une réponse"
#     )

#     def __str__(self):
#         return f'Reply by {self.author} on {self.post}' if self.parent else f'Comment by {self.author} on {self.post}'

class Category(models.Model):
    """
    Catégorisation des articles, permet l’imbrication de sous-catégories.
    """
    name = models.CharField(
        max_length=100, help_text="Nom de la catégorie"
    )
    parent = models.ForeignKey(
        'self', on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='subcategories',
        help_text="Catégorie parent, pour structure arborescente"
    )
    description = models.TextField(blank=True, help_text="Description facultative")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Date de création")

    def __str__(self):
        return self.name if not self.parent else f"{self.parent} > {self.name}"

class Tag(models.Model):
    """
    Mot-clé unique associé à des articles du blog.
    """
    name = models.CharField(
        max_length=64, unique=True, help_text="Nom du tag (unique)"
    )

    def __str__(self):
        return self.name


# class Blog_index_Page(Page):
#     parent_page_types = ['wagtailcore.Page']
#     subpage_types = ['blog.BlogPost']


# class BlogPostPage(Page):
#     template = "blog/blog_post_page.html"

#     STATUS_CHOICES = [
#         ('draft', 'Brouillon'),
#         ('scheduled', 'Planifié'),
#         ('finished', 'Terminé'),
#         ('published', 'Publié'),
#     ]

#     content_html = RichTextField(features=["bold", "italic", "link", "image", "code"])
#     excerpt = models.TextField(max_length=300, blank=True)
#     featured_image = models.ForeignKey(
#         'wagtailimages.Image',
#         on_delete=models.SET_NULL,
#         null=True, blank=True,
#         related_name='+',
#     )
#     status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='draft')
#     meta_title = models.CharField(max_length=200, blank=True)
#     meta_description = models.TextField(blank=True)
#     publishing_date = models.DateTimeField(null=True, blank=True)

#     content_panels = Page.content_panels + [
#         FieldPanel("content_html"),
#         FieldPanel("excerpt"),
#         FieldPanel("featured_image"),
#         FieldPanel("status"),
#         FieldPanel("publishing_date"),
#     ]

#     promote_panels = Page.promote_panels + [
#         MultiFieldPanel([
#             FieldPanel("meta_title"),
#             FieldPanel("meta_description"),
#         ], heading="SEO"),
#     ]

# class CategoryPage(Page):
#     description = models.TextField(blank=True)
    
#     content_panels = Page.content_panels + [
#         FieldPanel("description"),
#     ]

#     parent_page_types = ['blog.BlogIndexPage']
#     subpage_types = ['blog.CategoryPage', 'blog.BlogPostPage']


# class BlogIndexPage(Page):
#     intro = RichTextField(blank=True)

#     content_panels = Page.content_panels + [
#         FieldPanel("intro"),
#     ]

#     subpage_types = ['blog.BlogPostPage', 'blog.CategoryPage']

#     def get_context(self, request):
#         context = super().get_context(request)
#         context['posts'] = BlogPostPage.objects.live().order_by('-first_published_at')
#         return context


# class Comment(models.Model):
#     post = models.ForeignKey(
#         'blog.BlogPostPage',
#         related_name='comments',
#         on_delete=models.CASCADE
#     )
#     author_name = models.CharField(max_length=120)
#     content = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)
#     parent = models.ForeignKey(
#         'self',
#         null=True, blank=True,
#         related_name='replies',
#         on_delete=models.CASCADE
#     )

#     def __str__(self):
#         return f"{self.author_name} - {self.post.title}"


# from modelcluster.fields import ParentalKey
# from modelcluster.tags import ClusterTaggableManager
# from taggit.models import TaggedItemBase

# class BlogPostTag(TaggedItemBase):
#     content_object = ParentalKey(
#         'BlogPostPage',
#         related_name='tagged_items',
#         on_delete=models.CASCADE
#     )

# class BlogPostPage(Page):
#     ...
#     tags = ClusterTaggableManager(through=BlogPostTag, blank=True)

#     content_panels = Page.content_panels + [
#         FieldPanel("content_html"),
#         FieldPanel("excerpt"),
#         FieldPanel("featured_image"),
#         FieldPanel("status"),
#         FieldPanel("publishing_date"),
#         FieldPanel("tags"),
#     ]

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

# class Comment(models.Model):
#     post = models.ForeignKey(
#         'blog.BlogPostPage',
#         related_name='comments',
#         on_delete=models.CASCADE
#     )
#     author_name = models.CharField(max_length=120)
#     content = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)
#     parent = models.ForeignKey(
#         'self',
#         null=True, blank=True,
#         related_name='replies',
#         on_delete=models.CASCADE
#     )

#     def __str__(self):
#         return f"{self.author_name} - {self.post.title}"




from auditlog.registry import auditlog

auditlog.register(BlogPost)
auditlog.register(Comment)
auditlog.register(Category)
auditlog.register(Tag)
auditlog.register(BlogPost.tags.through)