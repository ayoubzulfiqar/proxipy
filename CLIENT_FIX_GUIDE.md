# Client-Side Fix Guide

## Problem Analysis

The error you're encountering is caused by the `extractImageUrls` function returning relative URLs (starting with `/`) instead of full URLs with schemes and domains. When these relative URLs are passed to the proxy, they fail validation.

## Root Cause

In your `extractImageUrls` function, you're adding URLs that are:

1. **Page URLs** (like fapello) instead of direct image URLs
2. **Relative URLs** that start with `/` without a domain
3. **Incomplete URLs** that lack proper scheme and domain

## Solution

### Option 1: Fix the URL Extraction Function

Update your `extractImageUrls` function to only return direct image URLs:

```javascript
export const extractImageUrls = (data) => {
  const imageUrls = new Set();

  if (!data.metadata_list || !Array.isArray(data.metadata_list)) {
    return [];
  }

  // Helper function to validate and add URL
  const addImageUrl = (url) => {
    if (!url) return;
    
    // Skip if it's a video URL
    if (isVideoUrl(url)) {
      console.log(`Filtered out video URL: ${url}`);
      return;
    }
    
    // Only add if it's a direct image URL with proper scheme
    if (isImageUrl(url) && (url.startsWith('http://') || url.startsWith('https://'))) {
      imageUrls.add(url);
    } else {
      console.log(`Filtered out invalid URL: ${url}`);
    }
  };

  data.metadata_list.forEach((item) => {
    // Only process direct image URLs, skip page URLs
    if (item.download_url) {
      // Only add if it's a direct image URL
      if (isImageUrl(item.download_url) && !isVideoUrl(item.download_url)) {
        addImageUrl(item.download_url);
      }
      // Skip page URLs - they should be handled separately
    }

    // DeviantArt patterns - only add direct image URLs
    if (item.content && item.content.src) addImageUrl(item.content.src);
    if (item.preview && item.preview.src) addImageUrl(item.preview.src);
    if (item.target && item.target.src) addImageUrl(item.target.src);
    if (item.thumbs && Array.isArray(item.thumbs)) {
      item.thumbs.forEach((thumb) => {
        if (thumb.src) addImageUrl(thumb.src);
      });
    }

    // 500px patterns
    if (item.image_url && Array.isArray(item.image_url)) {
      item.image_url.forEach(addImageUrl);
    }
    if (item.images && Array.isArray(item.images)) {
      item.images.forEach((img) => {
        if (img.https_url) addImageUrl(img.https_url);
        if (img.url) addImageUrl(img.url);
      });
    }

    // Other patterns - only add direct image URLs
    if (item.file_url) addImageUrl(item.file_url);
    if (item.preview_url) addImageUrl(item.preview_url);
    if (item.thumbnail_url) addImageUrl(item.thumbnail_url);
    if (item.asset && item.asset.image_url) addImageUrl(item.asset.image_url);
    if (item.cover_url) addImageUrl(item.cover_url);
    if (item.link) addImageUrl(item.link);
    if (item.thumbnail) addImageUrl(item.thumbnail);
    if (item.url) addImageUrl(item.url);
    
    // Tenor patterns
    if (item.media_formats) {
      Object.values(item.media_formats).forEach((format) => {
        if (format.url) addImageUrl(format.url);
      });
    }
  });

  return Array.from(imageUrls);
};
```

### Option 2: Add URL Validation Function

Create a helper function to validate URLs before sending them to the proxy:

```javascript
// Helper function to validate URLs
function isValidImageUrl(url) {
  if (!url) return false;
  
  // Must start with http:// or https://
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return false;
  }
  
  // Must be an image URL (not video)
  if (isVideoUrl(url)) return false;
  
  // Must be an image URL
  return isImageUrl(url);
}

// Helper function to fix relative URLs
function fixRelativeUrl(url, baseUrl = 'https://example.com') {
  if (!url) return null;
  
  // If it's already a full URL, return as-is
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return url;
  }
  
  // If it starts with /, it's relative - add base URL
  if (url.startsWith('/')) {
    return baseUrl + url;
  }
  
  // If it doesn't start with /, it might be a domain
  return 'https://' + url;
}

// Updated proxy URL creation
function createProxyUrl(imageUrl, baseUrl = 'https://example.com') {
  // Fix relative URLs
  const fixedUrl = fixRelativeUrl(imageUrl, baseUrl);
  
  // Validate the URL
  if (!isValidImageUrl(fixedUrl)) {
    console.error(`Invalid image URL: ${imageUrl}`);
    return null;
  }
  
  return `http://localhost:6969/proxy?url=${encodeURIComponent(fixedUrl)}`;
}
```

### Option 3: Use Current Domain for Relative URLs

If you need to handle page URLs that contain relative image paths:

```javascript
// Get current domain
const getCurrentDomain = () => {
  return window.location.origin; // e.g., "https://example.com"
};

// Enhanced URL fixing
function getFullImageUrl(relativeUrl) {
  if (!relativeUrl) return null;
  
  // If already a full URL, return as-is
  if (relativeUrl.startsWith('http://') || relativeUrl.startsWith('https://')) {
    return relativeUrl;
  }
  
  // If it's a relative URL, add current domain
  if (relativeUrl.startsWith('/')) {
    const currentDomain = getCurrentDomain();
    return currentDomain + relativeUrl;
  }
  
  // Handle other cases
  return 'https://' + relativeUrl;
}

// Updated proxy URL creation
const proxyUrl = `http://localhost:6969/proxy?url=${encodeURIComponent(
  getFullImageUrl(imageUrl)
)}`;
```

## Testing Your Fix

After implementing the fix, test with:

```javascript
// Test cases
const testUrls = [
  '/photo/1113051214/Gaurdian-by-Marc-Adamus', // Relative URL (should be fixed)
  'https://example.com/image.jpg', // Full URL (should work)
  'image.jpg', // Relative without slash (should be fixed)
  'https://example.com/video.mp4', // Video URL (should be filtered)
];

testUrls.forEach(url => {
  const fixedUrl = getFullImageUrl(url);
  const proxyUrl = `http://localhost:6969/proxy?url=${encodeURIComponent(fixedUrl)}`;
  console.log(`Original: ${url}`);
  console.log(`Fixed: ${fixedUrl}`);
  console.log(`Proxy: ${proxyUrl}`);
  console.log('---');
});
```

## Recommended Approach

I recommend **Option 1** (fixing the URL extraction function) because:

1. **Security**: Only processes direct image URLs, avoiding potential SSRF issues
2. **Performance**: Reduces unnecessary proxy requests for page URLs
3. **Reliability**: Ensures all URLs are valid before sending to proxy
4. **Maintainability**: Clear separation of concerns

## Why This Fix is Important

The security fix I implemented prevents:

- **SSRF Attacks**: Relative URLs could be exploited to access internal resources
- **Confusion**: Clear error messages help developers understand what's wrong
- **Security**: Only full, properly formatted URLs are accepted

This is a security improvement that protects your application while providing clear guidance to developers.
