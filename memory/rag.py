"""
RAG (Retrieval-Augmented Generation) with ChromaDB
Long-term memory and context management for the agent
"""

import chromadb
from chromadb.config import Settings
import logging
from typing import List, Optional
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class RAGManager:
    """
    Manages vector storage and retrieval using ChromaDB.
    
    Responsibilities:
    1. Store execution results and vulnerabilities
    2. Retrieve relevant context during reasoning
    3. Maintain learning across multiple targets
    """
    
    def __init__(self, db_path: str = "./chroma_db", collection_name: str = "red_agent"):
        """
        Initialize ChromaDB client.
        
        Args:
            db_path: Path to ChromaDB storage
            collection_name: Name of the collection
        """
        
        self.db_path = db_path
        self.collection_name = collection_name
        
        try:
            # Initialize Chroma client (persisted)
            settings = Settings(
                chroma_db_impl="duckdb+parquet",
                persist_directory=db_path,
                anonymized_telemetry=False,
            )
            self.client = chromadb.Client(settings)
            
            # Get or create collection
            self.collection = self.client.get_or_create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            
            logger.info(f"ChromaDB initialized at {db_path}")
        except Exception as e:
            logger.error(f"Error initializing ChromaDB: {e}")
            raise
    
    def store_finding(self, finding_type: str, content: str, metadata: dict = None) -> str:
        """
        Store a finding (vulnerability, exploit result, etc.) in ChromaDB.
        
        Args:
            finding_type: Type of finding (vulnerability, exploit, service, etc.)
            content: The finding content
            metadata: Additional metadata (target, severity, etc.)
        
        Returns:
            Document ID
        """
        
        if metadata is None:
            metadata = {}
        
        metadata["type"] = finding_type
        metadata["timestamp"] = datetime.now().isoformat()
        
        try:
            # Generate a unique ID
            doc_id = f"{finding_type}_{datetime.now().timestamp()}"
            
            # Add to collection
            self.collection.add(
                ids=[doc_id],
                documents=[content],
                metadatas=[metadata]
            )
            
            logger.debug(f"Stored finding: {doc_id}")
            return doc_id
        except Exception as e:
            logger.error(f"Error storing finding: {e}")
            raise
    
    def store_vulnerability(self, vulnerability: dict) -> str:
        """
        Store a discovered vulnerability.
        
        Args:
            vulnerability: VulnerabilityFinding dict
        
        Returns:
            Document ID
        """
        
        content = f"{vulnerability['type']} at {vulnerability['location']}: {vulnerability['description']}"
        metadata = {
            "type": "vulnerability",
            "severity": vulnerability['severity'],
            "location": vulnerability['location'],
            "vulnerability_type": vulnerability['type'],
            "target": vulnerability.get('target', 'unknown'),
        }
        
        return self.store_finding("vulnerability", content, metadata)
    
    def store_execution(self, execution: dict, target: str = "") -> str:
        """
        Store a tool execution result for future reference.
        
        Args:
            execution: ToolExecution dict
            target: Target being tested
        
        Returns:
            Document ID
        """
        
        content = f"Tool: {execution['tool_name']}\n"
        content += f"Status: {execution['status'].value}\n"
        content += f"Output: {execution['stdout'][:200]}"
        
        metadata = {
            "type": "execution",
            "tool": execution['tool_name'],
            "status": execution['status'].value,
            "target": target,
        }
        
        return self.store_finding("execution", content, metadata)
    
    def retrieve(self, query: str, k: int = 5) -> List[str]:
        """
        Retrieve relevant findings from memory.
        
        Args:
            query: Search query (e.g., "SQL injection vulnerabilities")
            k: Number of results to return
        
        Returns:
            List of relevant documents
        """
        
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=k
            )
            
            if results and results['documents']:
                documents = results['documents'][0]  # First query's results
                logger.debug(f"Retrieved {len(documents)} relevant documents")
                return documents
            else:
                logger.debug("No relevant documents found")
                return []
        except Exception as e:
            logger.error(f"Error retrieving from ChromaDB: {e}")
            return []
    
    def retrieve_by_target(self, target: str, k: int = 10) -> List[str]:
        """
        Retrieve all findings for a specific target.
        
        Args:
            target: Target IP/URL
            k: Max results
        
        Returns:
            List of relevant findings
        """
        
        try:
            results = self.collection.get(
                where={"target": {"$eq": target}},
                limit=k
            )
            
            if results and results['documents']:
                return results['documents']
            return []
        except Exception as e:
            logger.error(f"Error retrieving by target: {e}")
            return []
    
    def retrieve_by_type(self, finding_type: str, k: int = 10) -> List[str]:
        """
        Retrieve findings by type (vulnerability, exploit, etc.).
        """
        
        try:
            results = self.collection.get(
                where={"type": {"$eq": finding_type}},
                limit=k
            )
            
            if results and results['documents']:
                return results['documents']
            return []
        except Exception as e:
            logger.error(f"Error retrieving by type: {e}")
            return []
    
    def get_statistics(self) -> dict:
        """Get collection statistics"""
        
        try:
            count = self.collection.count()
            return {
                "collection": self.collection_name,
                "total_documents": count,
                "db_path": self.db_path
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    def clear_collection(self):
        """
        Clear the collection (for testing/reset).
        Use with caution!
        """
        
        try:
            self.client.delete_collection(self.collection_name)
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            logger.warning("ChromaDB collection cleared")
        except Exception as e:
            logger.error(f"Error clearing collection: {e}")
