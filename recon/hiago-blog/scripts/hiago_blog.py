#!/usr/bin/env python3
"""
hiago.sh Blog Extractor — Extracts blog post content from Next.js RSC payload.
Usage:
    python3 hiago_blog.py                              # List all posts
    python3 hiago_blog.py <post-id>                     # Show specific post
    python3 hiago_blog.py --json                        # Output all posts as JSON
    python3 hiago_blog.py --search <keyword>            # Search all posts
"""

import re, json, sys, html as html_mod, urllib.request

URL = "https://www.hiago.sh/"

def fetch_page(url=URL):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; HermesAgent)"
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="replace")

def decode_rsc(html):
    chunks = re.findall(r'self\.__next_f\.push\(\[1,"(.*?)"\]\)', html, re.DOTALL)
    full = ""
    for chunk in chunks:
        try:
            full += chunk.encode().decode("unicode_escape")
        except:
            full += chunk
    return full

def extract_balanced_json(text, marker):
    """Extract balanced JSON starting after marker."""
    idx = text.find(marker)
    if idx < 0:
        return None
    start = idx + len(marker)
    # Find the opening bracket
    while start < len(text) and text[start] != "[":
        start += 1
    if start >= len(text):
        return None
    depth = 0
    for i, c in enumerate(text[start:]):
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return text[start:start + i + 1]
    return None

def extract_post_content(full_text, post_id):
    """Extract HTML content for a specific post from the RSC."""
    # The post content is embedded as raw HTML in the decoded text
    # Find the post by its ID marker
    markers = [
        f'id="{post_id}"',
        f'#{post_id}',
        f'post-{post_id}',
    ]
    for marker in markers:
        idx = full_text.find(marker)
        if idx >= 0:
            # Extract a generous chunk of content around the marker
            start = max(0, idx - 500)
            end = min(len(full_text), idx + 15000)
            return full_text[start:end]
    return ""

def strip_html(text):
    text = re.sub(r"<[^>]+>", "", text)
    text = html_mod.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def get_articles(full_text):
    """Get article metadata from RSC payload."""
    raw = extract_balanced_json(full_text, '"articles"')
    if not raw:
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []

def main():
    # Fetch main page for index
    html = fetch_page()
    full = decode_rsc(html)
    articles = get_articles(full)
    
    if not articles:
        print("Error: Could not find blog articles.")
        return 1
    
    if len(sys.argv) == 1 or sys.argv[1] == "--list":
        print(f"\nhiago.sh — Blog ({len(articles)} posts)\n")
        for a in articles:
            print(f"  {a['id']:25s} {a['title'][:55]:55s} {a.get('meta','')}")
        print(f"\n  Usage: {sys.argv[0]} <post-id>")
        return
    
    if sys.argv[1] == "--json":
        print(json.dumps(articles, indent=2, ensure_ascii=False))
        return
    
    if sys.argv[1] == "--search" and len(sys.argv) > 2:
        keyword = sys.argv[2].lower()
        print(f"\nSearching for '{keyword}' in all posts...\n")
        for a in articles:
            if keyword in a.get("title", "").lower() or keyword in a.get("summary", "").lower():
                print(f"  {a['id']:25s} {a['title']}")
        return
    
    # Specific post — fetch with ?post= parameter
    post_id = sys.argv[1]
    print(f"Fetching {post_id}...", file=sys.stderr)
    post_html = fetch_page(f"{URL}?post={post_id}")
    post_full = decode_rsc(post_html)
    
    # Find article info
    article = None
    for a in articles:
        if a["id"] == post_id:
            article = a
            break
    
    if article:
        print(f"# {article['title']}")
        print(f"Published: {article.get('meta', '')}")
        print(f"Tags: {', '.join(article.get('tags', []))}")
        print()
    
    # Extract content from decoded RSC
    # The post HTML is embedded in the decoded text - find content header tags
    markers = ["<h1", "<h2", "<article", "<main", "<p>", "<p >"]
    content_start = len(post_full)
    for m in markers:
        i = post_full.find(m, 5000)  # Skip metadata before 5k
        if 0 < i < content_start:
            content_start = i
    
    if content_start < len(post_full):
        content_end = min(len(post_full), content_start + 30000)
        raw = post_full[content_start:content_end]
        # Find natural break point (end of content section)
        section_end = raw.find("</article>")
        if section_end >= 0:
            raw = raw[:section_end]
        cleaned = strip_html(raw)
        # Remove short lines (noise)
        lines = [l for l in cleaned.split("\n") if len(l.strip()) > 3]
        if lines:
            print("\n".join(lines[:200]))
        else:
            print(cleaned[:8000])
    
    print(f"\n---\nFull post: {article.get('url', 'N/A') if article else ''}")
    print(f"Source: {URL}?post={post_id}")

if __name__ == "__main__":
    sys.exit(main())
