from django.contrib import admin
from .models import BlogPost, Comment, Category, Tag

# Register your models here.

@admin.register(BlogPost)
class BlogPostAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'status', 'publishing_date', 'created_at')
    list_filter = ('status', 'publishing_date', 'author', 'category')
    search_fields = ('title', 'content_html', 'excerpt', 'author__username')
    prepopulated_fields = {'slug': ('title',)}
    ordering = ('-created_at',)
    filter_horizontal = ('tags',)
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        (None, {
            'fields': ('title', 'slug', 'content_html', 'excerpt', 'author', 'category', 'tags', 'featured_image')
        }),
        ('Publication', {
            'fields': ('status', 'publishing_date')
        }),
        ('SEO', {
            'fields': ('meta_title', 'meta_description')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('author_name', 'post', 'created_at', 'parent')
    list_filter = ('created_at', 'author_name')
    search_fields = ('content', 'author__username', 'post__title')

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'parent')
    search_fields = ('name',)
    list_filter = ('parent',)

@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)
