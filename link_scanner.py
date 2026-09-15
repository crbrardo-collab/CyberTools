import pandas as pd
import streamlit as st

def process_bulk_csv(uploaded_file):
    # Read the uploaded CSV into a Pandas Dataframe
    df = pd.read_csv(uploaded_file)
    
    st.write("### Data Preview")
    st.dataframe(df.head(5), use_container_width=True)

    # Dynamically detect columns so the user can choose which one holds the links
    link_column = st.selectbox("Select the column containing the links/URLs:", df.columns)

    if st.button("Extract & Analyze Links"):
        # Extract the selected column, remove empty rows, and convert to a list
        links = df[link_column].dropna().tolist()
        
        st.success(f"Successfully extracted {len(links)} links ready for analysis.")
        
        # Display the extracted links cleanly
        for link in links:
            st.code(link)
            
        return links
    return None