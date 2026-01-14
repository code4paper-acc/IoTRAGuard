#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import subprocess
from dataclasses import dataclass
from tree_sitter import Tree, Node
from tree_sitter_languages import get_parser


@dataclass
class Span:
    start: int
    end: int

    def __post_init__(self):
        """Enforce start <= end; automatically correct invalid values during initialization."""
        if self.start > self.end:
            self.start, self.end = self.end, self.start

    def extract(self, s: str) -> str:
        """Extract text within the range."""
        return s[self.start: self.end]

    def extract_lines(self, s: str, cover_content: int = 150) -> str:
        """Extract text within line ranges and supplement with context."""
        lines = s.splitlines()
        # Ensure line numbers are within bounds
        start_line = max(0, self.start)
        end_line = min(len(lines), self.end)
        
        # Get preceding context
        before_lines = lines[:start_line][::-1]  # Reverse to facilitate cumulative length calculation
        before_chunk = []
        chunk_len = 0
        for line in before_lines:
            chunk_len += len(line)
            if chunk_len >= cover_content:
                break
            before_chunk.append(line)
        before_chunk.reverse()  # Restore original order
        
        # Get succeeding context
        after_lines = lines[end_line:]
        after_chunk = []
        chunk_len = 0
        for line in after_lines:
            chunk_len += len(line)
            if chunk_len >= cover_content:
                break
            after_chunk.append(line)
        
        # Merge context and core chunk
        core_chunk = lines[start_line:end_line]
        return "\n".join(before_chunk + core_chunk + after_chunk)

    def __add__(self, other):
        """Merge two Spans or offset a Span."""
        if isinstance(other, int):
            return Span(self.start + other, self.end + other)
        elif isinstance(other, Span):
            return Span(self.start, other.end)
        else:
            raise NotImplementedError(f"Unsupported type for __add__: {type(other)}")

    def __len__(self) -> int:
        """Enforce non-negative length."""
        return max(0, self.end - self.start)


def get_line_number(index: int, source_code: str) -> int:
    """Get line number based on character index (0-based)."""
    total_chars = 0
    for line_number, line in enumerate(source_code.splitlines(keepends=True)):
        total_chars += len(line)
        if total_chars > index:
            return line_number
    return len(source_code.splitlines()) - 1  # Last line


def non_whitespace_len(s):
    """Calculate length of non-whitespace characters."""
    if isinstance(s, bytes):
        s = s.decode('utf-8', errors='ignore')
    return len(re.sub(r"\s", "", s))


def chunker(
        tree: Tree,
        source_code: str,
        MAX_CHARS=512 * 5,
        coalesce=150,
        max_recursion_depth=1000
) -> list[Span]:
    """Code chunking based on syntax tree (iterative implementation to avoid recursion overflow)."""
    
    def chunk_node_iterative(root_node: Node) -> list[Span]:
        chunks: list[Span] = []
        # Stack elements: (current_node, current_chunk, depth)
        stack = [(root_node, Span(root_node.start_byte, root_node.start_byte), 0)]
        
        while stack:
            node, current_chunk, depth = stack.pop()
            
            # Exceeding max depth limit, treat node as an independent chunk
            if depth > max_recursion_depth:
                node_span = Span(node.start_byte, node.end_byte)
                if len(node_span) > 0:
                    chunks.append(node_span)
                continue
            
            # Process child nodes in reverse (to maintain original order)
            for child in reversed(node.children):
                child_span = Span(child.start_byte, child.end_byte)
                child_len = len(child_span)
                
                # Skip empty nodes
                if child_len == 0:
                    continue
                
                # Child node too large, process separately
                if child_len > MAX_CHARS:
                    if len(current_chunk) > 0:
                        chunks.append(current_chunk)
                    # Push child node to stack, create new empty chunk
                    stack.append((child, Span(child.end_byte, child.end_byte), depth + 1))
                else:
                    # Check if merged size exceeds limit
                    merged_span = Span(current_chunk.start, child_span.end)
                    if len(merged_span) > MAX_CHARS:
                        # Save current chunk, create new chunk for child node
                        if len(current_chunk) > 0:
                            chunks.append(current_chunk)
                        current_chunk = child_span
                    else:
                        # Merge into current chunk
                        current_chunk = merged_span
            
            # Save current chunk (only if non-empty)
            if len(current_chunk) > 0:
                chunks.append(current_chunk)
        
        # Deduplicate (avoid duplicate chunks)
        unique_chunks = []
        seen = set()
        for span in chunks:
            key = (span.start, span.end)
            if key not in seen and len(span) > 0:
                seen.add(key)
                unique_chunks.append(span)
        return unique_chunks

    # Generate initial chunks
    chunks = chunk_node_iterative(tree.root_node)
    if not chunks:
        return []

    # Fill gaps between chunks (ensure continuity without overlap)
    for i in range(len(chunks) - 1):
        prev = chunks[i]
        curr = chunks[i + 1]
        if curr.start > prev.end:
            prev.end = curr.start  # Fill gap
        curr.start = prev.end  # Ensure continuity

    # Merge chunks that are too small
    new_chunks = []
    current_chunk = Span(0, 0)
    for span in chunks:
        if len(span) == 0:
            continue
        
        # Initialize current chunk
        if len(current_chunk) == 0:
            current_chunk = span
        else:
            current_chunk = Span(current_chunk.start, span.end)
        
        # Save current chunk if conditions are met
        content = current_chunk.extract(source_code)
        if non_whitespace_len(content) > coalesce and "\n" in content:
            new_chunks.append(current_chunk)
            current_chunk = Span(0, 0)
    
    # Add remaining chunks
    if len(current_chunk) > 0:
        new_chunks.append(current_chunk)

    # Convert to line number intervals
    line_chunks = []
    for span in new_chunks:
        start_line = get_line_number(span.start, source_code)
        end_line = get_line_number(span.end, source_code)
        line_span = Span(start_line, end_line)
        if len(line_span) > 0:
            line_chunks.append(line_span)
    
    return line_chunks


def mkdir(path):
    """Create directory (if it does not exist)."""
    if not os.path.exists(path):
        os.makedirs(path)


def remove_import(content: str) -> str:
    """Remove import statements and comments from code (multi-language support)."""
    content = re.sub(r'#\s*include\s*[^\n]+\n', '', content)
    content = re.sub(r'#\s*define\s*[^\n]+\n', '', content)
    content = re.sub(r'/\*[\s\S]*?\*/', '', content)  # Multi-line comments
    content = re.sub(r'//[^\n]+\n', '', content)       # Single-line comments
    
    content = re.sub(r'import {(.|\n)*} from.*[^\n]+\n', '', content)
    content = re.sub(r'import [^\n]+\n', '', content)
    return content


def is_thrift(content: str) -> bool:
    """Determine if it is Thrift auto-generated code."""
    return content.startswith('''/**
 * Autogenerated by Thrift Compiler (0.9.3)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 * @generated
 */''')


def get_current_commit_info(repo_path: str) -> str:
    """Get commit version info of current repository (first 8 characters of commit hash)."""
    try:
        # Execute git command to get current commit hash
        result = subprocess.run(
            ['git', '-C', repo_path, 'rev-parse', '--short=8', 'HEAD'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Return default value if not a git repo or git command missing
        return "unknown"


class Documents:
    """Chunked document object."""
    def __init__(self, path: str = '', index: int = 0, content: str = '', version: str = '') -> None:
        self.path = path
        self.index = index
        self.content = content
        self.version = version  # New version field


def split_to_segmenmt(
        project_path: str, 
        max_chars: int = 512 * 5, 
        cover_content: int = 150,
        version: str = None  # Allow external version specification
) -> list[Documents]:
    """Split project code files into chunked documents, supporting version info recording."""
    # Supported file suffixes (including C/C++)
    suffix = ("java", "py", "c", "h", "cpp")
    
    # Mapping suffix to tree-sitter language
    suffix_map = {
        "java": "java",
        "py": "python",
        "c": "c",
        "h": "c",
        "cpp": "cpp"
    }
    
    # Preload parsers
    parse_map = {lang: get_parser(lang) for lang in suffix_map.values()}
    
    documents = []
    
    # Save current branch to restore later
    original_branch = None
    try:
        # If version is specified, switch to that version
        if version:
            # Get current branch - Modified: use subprocess.run instead of check_output to avoid parameter conflicts
            result = subprocess.run(
                ['git', '-C', project_path, 'rev-parse', '--abbrev-ref', 'HEAD'],
                capture_output=True,
                text=True
            )
            original_branch = result.stdout.strip()
            
            # Switch to specified version
            subprocess.run(
                ['git', '-C', project_path, 'checkout', version, '--quiet'],
                check=True,
                capture_output=True,
                text=True
            )
        
        # Get version info: prioritize external specification, otherwise auto-fetch git commit
        doc_version = version or get_current_commit_info(project_path)
        
        # Traverse project directory
        for root, _, files in os.walk(os.path.expanduser(project_path)):
            for file in files:
                # Extract file suffix
                suf = file.split('.')[-1].lower()
                if suf not in suffix:
                    continue
                
                file_path = os.path.join(root, file)
                
                # If version specified, check if file exists in that version
                if version:
                    rel_path = os.path.relpath(file_path, project_path)
                    try:
                        # Check if file exists in specified version - Modified: use run instead of check_output
                        subprocess.run(
                            ['git', '-C', project_path, 'cat-file', '-e', f'{version}:{rel_path}'],
                            capture_output=True,
                            text=True,
                            check=True
                        )
                    except subprocess.CalledProcessError:
                        # File does not exist in specified version, skip
                        continue
                
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                except (UnicodeDecodeError, IOError):
                    # Skip unreadable files
                    continue
                
                # Skip Thrift auto-generated code
                if is_thrift(content):
                    continue
                
                # Clean code (remove imports and comments)
                content_clean = remove_import(content)
                if not content_clean.strip():
                    continue  # Skip empty files
                
                # Parse code to generate syntax tree
                lang = suffix_map[suf]
                parser = parse_map[lang]
                tree = parser.parse(bytes(content_clean, 'utf-8'))
                
                # Chunk and generate document objects (including version info)
                for segment_idx, chunk in enumerate(chunker(tree, content_clean, max_chars)):
                    chunk_content = chunk.extract_lines(content, cover_content)
                    documents.append(Documents(
                        path=file_path,
                        index=segment_idx,
                        content=chunk_content,
                        version=doc_version  # Store version info
                    ))
    
    finally:
        # Switch back to original branch
        if version and original_branch:
            try:
                subprocess.run(
                    ['git', '-C', project_path, 'checkout', original_branch, '--quiet'],
                    check=True,
                    capture_output=True,
                    text=True
                )
            except subprocess.CalledProcessError as e:
                print(f"Warning: Failed to switch back to original branch {original_branch}: {e.stderr}")
    
    return documents