from django.db import models
from django.utils import timezone
from django.utils.text import slugify
from accounts.models import CustomUser
from tinymce.models import HTMLField

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

class Comment(models.Model):
    """
    Commentaire sur un article de blog, avec possibilité de répondre à un autre commentaire.
    """
    post = models.ForeignKey(
        BlogPost, related_name='comments',
        on_delete=models.CASCADE,
        help_text="Article associé au commentaire"
    )
    author = models.ForeignKey(
        CustomUser, on_delete=models.PROTECT,
        help_text="Auteur du commentaire"
    )
    content = models.TextField(help_text="Contenu du commentaire")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Date de création")
    parent = models.ForeignKey(
        'self',
        null=True, blank=True,
        related_name='replies',
        on_delete=models.CASCADE,
        help_text="Commentaire parent si ce commentaire est une réponse"
    )

    def __str__(self):
        return f'Reply by {self.author} on {self.post}' if self.parent else f'Comment by {self.author} on {self.post}'

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