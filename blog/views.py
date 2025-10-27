from django.shortcuts import render
from django.core.paginator import Paginator
from .models import *
from django.shortcuts import get_object_or_404

# Create your views here.
def blog_default(request):
    blog_posts_query = BlogPost.objects.all()
    blog_categories = Category.objects.all()
    blog_tags = Tag.objects.all()
    # blog_authors = BlogAuthor.objects.all()
    blog_comments = Comment.objects.all()

    paginator = Paginator(blog_posts_query, 10)
    page_number = request.GET.get('page')
    blog_posts = paginator.get_page(page_number)

    context = {
        'blog_posts': blog_posts,
        'blog_categories': blog_categories,
        'blog_tags': blog_tags,
        # 'blog_authors': blog_authors,
        'blog_comments': blog_comments,
    }
    return render(request, 'blog/blog-default.html', context)

def blog_post_detail(request, slug):
    blog_post = get_object_or_404(BlogPost, slug=slug)
    context = {
        'blog_post': blog_post
    }
    return render(request, 'blog/blog-post-detail.html', context)