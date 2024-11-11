from mastodon import Mastodon
import networkx as nx
import matplotlib.pyplot as plt

CLIENT_ID = 'YOUR_CLIENT_ID'
CLIENT_SECRET = 'YOUR_CLIENT_SECRET'
ACCESS_TOKEN = 'YOUR_ACCESS_TOKEN'

mastodon = Mastodon(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    access_token=ACCESS_TOKEN,
    api_base_url='https://infosec.exchange',
    ratelimit_method='pace'
)

def build_social_graph(username, max_depth=1):
    G = nx.DiGraph()
    visited = set()
    user = mastodon.account_lookup(f'@{username}@infosec.exchange')
    if not user:
        print("User not found.")
        return None
    user_id = user['id']
    def add_connections(current_id, depth):
        if depth > max_depth or current_id in visited:
            return
        visited.add(current_id)
        account = mastodon.account(current_id)
        G.add_node(current_id, username=account['username'])
        def fetch_all(api_call, account_id):
            results = []
            next_page = api_call(account_id)
            while next_page:
                results.extend(next_page)
                next_page = mastodon.fetch_next(next_page)
            return results
        try:
            followers = fetch_all(mastodon.account_followers, current_id)
            following = fetch_all(mastodon.account_following, current_id)
            for follower in followers:
                G.add_node(follower['id'], username=follower['username'])
                G.add_edge(follower['id'], current_id)
            for followee in following:
                G.add_node(followee['id'], username=followee['username'])
                G.add_edge(current_id, followee['id'])
                add_connections(followee['id'], depth + 1)
        except Exception as e:
            print(f"Error fetching connections for user {current_id}: {e}")
    add_connections(user_id, 0)
    return G

def visualize_graph(G):
    pos = nx.spring_layout(G, k=0.1)
    labels = {node: data['username'] for node, data in G.nodes(data=True)}
    plt.figure(figsize=(15, 15))
    nx.draw(G, pos, labels=labels, node_size=50, edge_color="gray", alpha=0.7, font_size=8)
    plt.title("Social Graph of Mastodon Users on infosec.exchange")
    plt.show()

username = 'exampleuser'  # Replace with the desired username
graph = build_social_graph(username, max_depth=1)
if graph:
    visualize_graph(graph)
