# Build the leakgauge arXiv note. Uses pdflatex directly (no latexmk needed);
# runs twice so refs/labels resolve. Manual thebibliography -> no bibtex pass.

TEX  = leakgauge.tex
PDF  = leakgauge.pdf

.PHONY: all clean

all: $(PDF)

$(PDF): $(TEX)
	pdflatex -interaction=nonstopmode -halt-on-error $(TEX)
	pdflatex -interaction=nonstopmode -halt-on-error $(TEX)

clean:
	rm -f *.aux *.log *.out *.toc $(PDF)
