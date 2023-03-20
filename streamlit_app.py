import streamlit as st
import feedparser

# RSS feed link
rss_link = "https://feed.podbean.com/whattheshell/feed.xml"

# Fetching the RSS feed
feed = feedparser.parse(rss_link)

# Displaying the title of the podcast
st.title(feed.feed.title)

# Looping through each episode and displaying its thumbnail and title
for episode in feed.entries:
    st.image(episode.links[1].href, width=150) # Displaying the thumbnail
    st.write(episode.title) # Displaying the episode title
