import pandas as pd
import streamlit as st
import re

def process_bulk_csv(uploaded_file):
    # Read the CSV
    df = pd.read_csv(uploaded_file)
    
    st.write("### Data Preview")
    st.dataframe(df.head(5), use_container_width=True)

    # We know your exact column names from the screenshot, but we use a selectbox 
    # and default to them just in case the format ever changes slightly.
    col_names = list(df.columns)
    
    default_id = col_names.index("ID") if "ID" in col_names else 0
    default_target = col_names.index("Unusual / Suspicious web link in the spam / scam message") if "Unusual / Suspicious web link in the spam / scam message" in col_names else 0

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
            # Convert IDs to strings to ensure perfect matching
            filtered_df[id_column] = filtered_df[id_column].astype(str).str.strip()
            search_id = last_id.strip()
            
            if search_id in filtered_df[id_column].values:
                # Find the row index of the exact ID match
                match_index = filtered_df.index[filtered_df[id_column] == search_id].tolist()[0]
                
                # Slice the dataframe to keep ONLY rows AFTER the matched index
                filtered_df = filtered_df.loc[match_index + 1:]
                st.info(f"⏭️ Skipped up to ID {search_id}. Processing the remaining {len(filtered_df)} rows.")
            else:
                st.warning(f"⚠️ ID {search_id} not found in the file. Processing all rows.")

        # Step 2: Extract the links from the Target column
        raw_data = filtered_df[target_column].dropna().astype(str).tolist()
        
        extracted_links = []
        for item in raw_data:
            item = item.strip()
            # Basic cleanup to ignore standard blanks from your screenshot
            if item.lower() in ['n/a', 'na', 'none', '-', '']:
                continue
            
            # (Optional) You could add regex here in the future to strip out sentences 
            # and keep ONLY URLs, but for now we grab the whole cell contents.
            extracted_links.append(item)
            
        if extracted_links:
            st.success(f"✅ Successfully extracted {len(extracted_links)} items.")
            
            with st.expander("View Extracted Links", expanded=True):
                # Print them out one by one
                for link in extracted_links:
                    st.code(link)
                    
            return extracted_links
        else:
            st.error("No data left to process after skipping.")
            
    return None