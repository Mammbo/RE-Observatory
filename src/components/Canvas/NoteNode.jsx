import { useState, useRef, useEffect, memo } from "react";
import { Handle, Position } from "@xyflow/react";
import ReactMarkdown from "react-markdown";

const NoteNode = ({ data }) => {
  const [markdown, setMarkdown] = useState(
    data?.content ||
      `# Welcome to Notes

Type **Markdown** here and see it render instantly.

- Supports lists
- Bold and *italic*
- \`code blocks\`
- And more!`
  );
  const [isEditing, setIsEditing] = useState(false);
  const textareaRef = useRef(null);

  useEffect(() => {
    if (isEditing && textareaRef.current) {
      textareaRef.current.focus();
      textareaRef.current.selectionStart = textareaRef.current.value.length;
    }
  }, [isEditing]);

  return (
    <div className="node-base nowheel w-75 h-75">
      {/* Content Area - both layers always in DOM for smooth transitions */}
      <div className="node-content">
        {/* Preview Layer */}
        <div
          onClick={() => setIsEditing(true)}
          className={`node-layer note-preview node-scrollbar
            ${isEditing ? "node-layer-hidden-up" : "node-layer-visible"}`}
        >
          <ReactMarkdown
            components={{
              h1: ({ node, ...props }) => <h1 className="md-h1" {...props} />,
              h2: ({ node, ...props }) => <h2 className="md-h2" {...props} />,
              h3: ({ node, ...props }) => <h3 className="md-h3" {...props} />,
              p: ({ node, ...props }) => <p className="md-p" {...props} />,
              ul: ({ node, ...props }) => <ul className="md-ul" {...props} />,
              ol: ({ node, ...props }) => <ol className="md-ol" {...props} />,
              li: ({ node, ...props }) => <li className="md-li" {...props} />,
              code: ({ node, inline, ...props }) =>
                inline ? (
                  <code className="md-code-inline" {...props} />
                ) : (
                  <code className="md-code-block" {...props} />
                ),
              pre: ({ node, ...props }) => <pre className="md-pre" {...props} />,
              blockquote: ({ node, ...props }) => (
                <blockquote className="md-blockquote" {...props} />
              ),
              strong: ({ node, ...props }) => (
                <strong className="md-strong" {...props} />
              ),
              em: ({ node, ...props }) => <em className="md-em" {...props} />,
              a: ({ node, ...props }) => <a className="md-a" {...props} />,
              hr: ({ node, ...props }) => <hr className="md-hr" {...props} />,
            }}
          >
            {markdown}
          </ReactMarkdown>
        </div>

        {/* Editor Layer */}
        <textarea
          ref={textareaRef}
          value={markdown}
          onChange={(e) => setMarkdown(e.target.value)}
          onBlur={() => setIsEditing(false)}
          placeholder="Write Markdown here..."
          className={`node-layer note-editor node-scrollbar
            ${isEditing ? "node-layer-visible" : "node-layer-hidden-down"}`}
        />
      </div>

      {/* Handles for connections - each side has source + target */}
      <Handle type="target" position={Position.Top} id="top-target" />
      <Handle type="source" position={Position.Top} id="top-source" />
      <Handle type="target" position={Position.Bottom} id="bottom-target" />
      <Handle type="source" position={Position.Bottom} id="bottom-source" />
      <Handle type="target" position={Position.Left} id="left-target" />
      <Handle type="source" position={Position.Left} id="left-source" />
      <Handle type="target" position={Position.Right} id="right-target" />
      <Handle type="source" position={Position.Right} id="right-source" />
    </div>
  );
};

export default memo(NoteNode);
