import pandas as pd
import streamlit as st
import re

def process_bulk_csv(uploaded_file):
    # Read the CSV
    df = pd.read_csv(uploaded_file)
    
    # We know your exact column names from the screenshot, but we use a selectbox 
    # and default to them just in case the format ever changes slightly.
    col_names = list(df.columns)
    
    default_id = col_names.index("ID") if "ID" in col_names else 0
    default_target = col_names.index("Unusual / Suspicious web link in the spam / scam message") if "Unusual / Suspicious web link in the spam / scam message" in col_names else 0

    st.markdown("#### Filter Settings")
    col1, col2 = st.columns(2)
    with col1:
        id_column = st.selectbox("Select ID Column:", col_names, index=default_id)
    with col2:
        target_column = st.selectbox("Select Target Link Column:", col_names, index=default_target)
        
    last_id = st.text_input("Enter Last Processed ID (e.g., 22092):", help="The script will start reading the row AFTER this ID.")

    if st.button("Extract Links"):
        filtered_df = df.copy()

        # Step 1: Find the ID and skip everything before and including it
        if last_id.strip():
            filtered_df[id_column] = filtered_df[id_column].astype(str).str.strip()
            search_id = last_id.strip()
            
            if search_id in filtered_df[id_column].values:
                match_index = filtered_df.index[filtered_df[id_column] == search_id].tolist()[0]
                filtered_df = filtered_df.loc[match_index + 1:]
                st.info(f"⏭️ Skipped up to ID {search_id}. Processing the remaining {len(filtered_df)} rows.")
            else:
                st.warning(f"⚠️ ID {search_id} not found in the file. Processing all rows.")

        # Step 2: Extract the raw data from the Target column
        raw_data = filtered_df[target_column].dropna().astype(str).tolist()
        
        # RegEx pattern to identify domains (e.g., example.com) and URLs (e.g., https://example.com/path)
        url_pattern = re.compile(r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?')
        
        extracted_links = []
        for item in raw_data:
            # Find all domain/URL matches in the current cell's text
            matches = url_pattern.findall(item)
            
            for match in matches:
                # Clean up any trailing punctuation that might get caught
                clean_match = match.rstrip('.,!?"\'')
                if clean_match:
                    extracted_links.append(clean_match)
            
        if extracted_links:
            st.success(f"✅ Successfully extracted {len(extracted_links)} isolated URLs/Domains.")
            
            with st.expander("View Extracted Links", expanded=True):
                # Print them out one by one cleanly
                for link in extracted_links:
                    st.code(link)
                    
            return extracted_links
        else:
            st.error("No valid links or domains found in the remaining data.")
            
    return None