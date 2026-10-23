// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlElementTables.java.

package sanitizer

//go:generate go run ../empiricism/cmd/canned-tables ../empiricism/canned-data.json html_element_tables_canned.go

import (
	"errors"
	"sort"
	"strings"
	"sync"
)

// TextNode is the pseudo element index for text nodes.
const TextNode = -1

// HTMLElementTables is metadata about HTML elements.
type HTMLElementTables struct {
	// elementNames maps between element indices and element names.
	elementNames *HTMLElementTablesHTMLElementNames
	// canContain relates elements and the elements that can contain them.
	canContain *htmlElementTablesDenseElementBinaryMatrix
	// closedOnCloseMatrix relates element names and the elements that are
	// closed when that close tag appears.
	closedOnCloseMatrix *htmlElementTablesDenseElementBinaryMatrix
	// closedOnOpenMatrix relates element names and the elements that are
	// closed when that open tag appears.
	closedOnOpenMatrix *htmlElementTablesDenseElementBinaryMatrix
	// explicitClosers are the close tags besides the tag itself which close
	// the tag.
	explicitClosers *HTMLElementTablesSparseElementToElements
	// impliedElementTable holds the elements, in order, which are implicitly
	// opened when a descendant tag is lexically nested within an ancestor.
	impliedElementTable *HTMLElementTablesSparseElementMultitable
	// textContentModel is the kind of character data that can appear in an
	// element.
	textContentModel *HTMLElementTablesTextContentModel
	// resumable are the elements that can be resumed after misnested inline
	// tags.
	resumable *HTMLElementTablesDenseElementSet

	dirTag      int
	olTag       int
	ulTag       int
	liTag       int
	selectTag   int
	optionTag   int
	optgroupTag int
	scriptTag   int
	styleTag    int
	tableTag    int
	tbodyTag    int
	tfootTag    int
	theadTag    int
	trTag       int
	tdTag       int
	thTag       int
	captionTag  int
	colTag      int
	colgroupTag int
	iframeTag   int
	templateTag int

	// freeWrappers is indexed by the descendant each wrapper applies to.
	freeWrappers []*htmlElementTablesFreeWrapper

	liTagArr []int

	// nofeatureElements are <noscript>, <noframes>, etc.
	nofeatureElements *HTMLElementTablesDenseElementSet
}

// NewHTMLElementTables bundles the element relationships extracted from a
// browser with the hard-coded tables needed to keep elements out of contexts
// whose scoping the browser probe cannot see.
func NewHTMLElementTables(
	elementNames *HTMLElementTablesHTMLElementNames,
	canContain *htmlElementTablesDenseElementBinaryMatrix,
	closedOnClose *htmlElementTablesDenseElementBinaryMatrix,
	closedOnOpen *htmlElementTablesDenseElementBinaryMatrix,
	explicitClosers *HTMLElementTablesSparseElementToElements,
	impliedElements *HTMLElementTablesSparseElementMultitable,
	textContentModel *HTMLElementTablesTextContentModel,
	resumable *HTMLElementTablesDenseElementSet,
) *HTMLElementTables {
	t := &HTMLElementTables{
		elementNames:        elementNames,
		canContain:          canContain,
		closedOnCloseMatrix: closedOnClose,
		closedOnOpenMatrix:  closedOnOpen,
		explicitClosers:     explicitClosers,
		impliedElementTable: impliedElements,
		textContentModel:    textContentModel,
		resumable:           resumable,
	}

	// Most of the information above is extracted by interrogating a browser
	// via html-containment.html
	// That does a good job of extracting relationships between elements.
	// It doesn't do such a good job with understanding scoping relationships
	// between elements, so we hard-code some tables needed to allow embedding
	// regardless of element scoping relationships that are extracted from the
	// HTML 5 spec.
	t.dirTag = t.IndexForName("dir")
	t.olTag = t.IndexForName("ol")
	t.ulTag = t.IndexForName("ul")
	t.liTag = t.IndexForName("li")
	t.selectTag = t.IndexForName("select")
	t.optionTag = t.IndexForName("option")
	t.optgroupTag = t.IndexForName("optgroup")
	t.scriptTag = t.IndexForName("script")
	t.styleTag = t.IndexForName("style")
	t.tableTag = t.IndexForName("table")
	t.tbodyTag = t.IndexForName("tbody")
	t.tfootTag = t.IndexForName("tfoot")
	t.theadTag = t.IndexForName("thead")
	t.trTag = t.IndexForName("tr")
	t.tdTag = t.IndexForName("td")
	t.thTag = t.IndexForName("th")
	t.captionTag = t.IndexForName("caption")
	t.colTag = t.IndexForName("col")
	t.colgroupTag = t.IndexForName("colgroup")
	t.iframeTag = t.IndexForName("iframe")
	t.templateTag = t.IndexForName("template")

	freeWrappers := []*htmlElementTablesFreeWrapper{
		newHTMLElementTablesFreeWrapper(
			t.liTag,
			// liTag is allowed here since an LI can appear when an LI is on
			// top of the stack.  It will be popped and the new LI will be
			// opened.
			[]int{t.dirTag, t.olTag, t.ulTag, t.liTag},
			[]int{t.ulTag}, false),
		// A template's contents hold an option or optgroup directly, as a
		// select does.
		newHTMLElementTablesFreeWrapper(
			t.optionTag,
			[]int{t.selectTag, t.optgroupTag, t.optionTag, t.templateTag},
			[]int{t.selectTag}, false),
		newHTMLElementTablesFreeWrapper(
			t.optgroupTag, []int{t.selectTag, t.optgroupTag, t.templateTag},
			[]int{t.selectTag}, false),
		newHTMLElementTablesFreeWrapper(
			t.tdTag, []int{t.trTag, t.tdTag, t.thTag},
			[]int{t.tableTag, t.tbodyTag, t.trTag}, true),
		newHTMLElementTablesFreeWrapper(
			t.thTag, []int{t.trTag, t.tdTag, t.thTag},
			[]int{t.tableTag, t.tbodyTag, t.trTag}, true),
		newHTMLElementTablesFreeWrapper(
			t.trTag, []int{t.tbodyTag, t.theadTag, t.tfootTag, t.trTag, t.tdTag, t.thTag},
			[]int{t.tableTag, t.tbodyTag}, true),
		newHTMLElementTablesFreeWrapper(
			t.tbodyTag, []int{t.tableTag, t.theadTag, t.tbodyTag, t.tfootTag},
			[]int{t.tableTag}, true),
		newHTMLElementTablesFreeWrapper(
			t.theadTag, []int{t.tableTag, t.theadTag, t.tbodyTag, t.tfootTag},
			[]int{t.tableTag}, true),
		newHTMLElementTablesFreeWrapper(
			t.tfootTag, []int{t.tableTag, t.theadTag, t.tbodyTag, t.tfootTag},
			[]int{t.tableTag}, true),
		newHTMLElementTablesFreeWrapper(
			t.captionTag,
			[]int{t.tableTag},
			[]int{t.tableTag}, true),
		newHTMLElementTablesFreeWrapper(
			t.colTag, []int{t.colgroupTag},
			[]int{t.tableTag, t.colgroupTag}, true),
		newHTMLElementTablesFreeWrapper(
			t.colgroupTag, []int{t.tableTag}, []int{t.tableTag},
			true),
	}
	maxDescIdx := -1
	for _, freeWrapper := range freeWrappers {
		maxDescIdx = max(freeWrapper.desc, maxDescIdx)
	}

	t.freeWrappers = make([]*htmlElementTablesFreeWrapper, maxDescIdx+1)
	for _, freeWrapper := range freeWrappers {
		t.freeWrappers[freeWrapper.desc] = freeWrapper
	}

	t.liTagArr = []int{t.liTag}

	nofeatureBits := make([]bool, t.NElementTypes())
	nofeatureBits[t.IndexForName("noscript")] = true
	nofeatureBits[t.IndexForName("noframes")] = true
	nofeatureBits[t.IndexForName("noembed")] = true
	t.nofeatureElements = NewHTMLElementTablesDenseElementSet(nofeatureBits)
	return t
}

// CanContain is true if parent can directly contain child.
func (t *HTMLElementTables) CanContain(parent, child int) bool {
	if t.nofeatureElements.Get(parent) {
		// It's hard to interrogate a browser about the behavior of
		// <noscript> in scriptless mode using JavaScript, and the
		// behavior of <noscript> is more dangerous when in that mode,
		// so we hardcode that mode here as a worst case assumption.
		return true
	}

	if child == TextNode {
		return t.CanContainText(parent)
	}
	return t.canContain.get(parent, child)
}

// IndexForName is the element index for the element with the given name.
func (t *HTMLElementTables) IndexForName(canonName string) int {
	return t.elementNames.GetElementNameIndex(canonName)
}

// CanonNameForIndex is the canonical name of the element with the given
// index.
func (t *HTMLElementTables) CanonNameForIndex(index int) string {
	return t.elementNames.CanonNames[index]
}

// Resumable reports whether the element can be resumed after misnested
// inline tags.
func (t *HTMLElementTables) Resumable(index int) bool {
	return t.resumable.Get(index)
}

// CanContainText reports whether parsing can produce an element with the
// given index that contains a text node.
func (t *HTMLElementTables) CanContainText(index int) bool {
	return t.textContentModel.CanContainText(index)
}

// CanContainPlainText reports whether parsing can produce an element with
// the given index that contains a text node that has human readable text
// instead of script or style source code.
func (t *HTMLElementTables) CanContainPlainText(index int) bool {
	return t.textContentModel.CanContainPlainText(index) &&
		// The iframe's content is specified in very odd ways
		// https://dev.w3.org/html5/pf-summary/Overview.html#the-iframe-element
		// """
		// When used in HTML documents, the allowed content model of iframe
		// elements is text, except that invoking the HTML fragment parsing
		// algorithm with the iframe element as the context element and the text
		// contents as the input must result in a list of nodes that are all
		// phrasing content, with no parse errors having occurred, with no
		// script elements being anywhere in the list or as descendants of
		// elements in the list, and with all the elements in the list
		// (including their descendants) being themselves conforming.
		//
		// The iframe element must be empty in XML documents.
		// """
		//
		// The iframe can contain text so canContain is true, but the text is
		// not freeform plain text.  The latter has the effect of making
		// HTMLPolicyBuilder built policies disallow text inside iframe
		// elements.
		index != t.iframeTag
}

// canContainComment reports whether element ix can contain a comment.
func (t *HTMLElementTables) canContainComment(ix int) bool {
	return t.textContentModel.CanContainComment(ix)
}

// canContainCharacterReference reports whether character references are
// decoded in the text of element ix.
func (t *HTMLElementTables) canContainCharacterReference(ix int) bool {
	return t.textContentModel.CanContainEntities(ix)
}

// isTextContentRaw reports whether element ix holds raw text, which is not
// parsed as markup.
func (t *HTMLElementTables) isTextContentRaw(ix int) bool {
	return t.textContentModel.IsRaw(ix)
}

// isUnended reports whether element ix, once open, runs to the end of the
// input.
func (t *HTMLElementTables) isUnended(ix int) bool {
	return t.textContentModel.IsUnended(ix)
}

// isAlternateCloserFor reports whether the end tag closeTag also closes an
// open openElement.
func (t *HTMLElementTables) isAlternateCloserFor(closeTag, openElement int) bool {
	return t.explicitClosers.get(openElement, closeTag)
}

// NElementTypes is the number of element types which is also the exclusive
// upper bound on element indices.
func (t *HTMLElementTables) NElementTypes() int {
	return len(t.elementNames.CanonNames)
}

// htmlElementTablesFreeWrapper names the containers that may hold an element
// directly, and the wrappers implied around it anywhere else.
type htmlElementTablesFreeWrapper struct {
	desc              int
	allowedContainers []bool
	implied           []int
	// pastEndCountsAsAllowed is whether an ancestor whose index lies past the
	// end of allowedContainers counts as allowed, the reading the table
	// parts' wrappers keep; false for the select and list wrappers, whose
	// set is exact.
	pastEndCountsAsAllowed bool
}

func newHTMLElementTablesFreeWrapper(
	desc int, allowedContainers, implied []int,
	pastEndCountsAsAllowed bool,
) *htmlElementTablesFreeWrapper {
	maxAllowedContainer := -1
	for _, allowedContainer := range allowedContainers {
		maxAllowedContainer = max(maxAllowedContainer, allowedContainer)
	}
	allowed := make([]bool, maxAllowedContainer+1)
	for _, allowedContainer := range allowedContainers {
		allowed[allowedContainer] = true
	}
	return &htmlElementTablesFreeWrapper{
		desc:                   desc,
		allowedContainers:      allowed,
		implied:                implied,
		pastEndCountsAsAllowed: pastEndCountsAsAllowed,
	}
}

// htmlElementTablesZeroInts is the empty element index list.
var htmlElementTablesZeroInts = []int{}

// impliedElements are the elements, in order, which are implicitly opened
// when a descendant tag is lexically nested within an ancestor.  Callers must
// not modify the returned slice.
func (t *HTMLElementTables) impliedElements(anc, desc int) []int {
	// <style> and <script> are allowed anywhere.
	if desc == t.scriptTag || desc == t.styleTag {
		return htmlElementTablesZeroInts
	}

	// It's dangerous to allow free <li> tags because of the way an <li>
	// implies a </li> if there is an <li> on the parse stack without a
	// LIST_SCOPE element in the middle.

	// Since we don't control the context in which sanitized HTML is embedded,
	// we can't assume that there isn't a containing <li> tag before parsing
	// starts, so we make sure we never produce an <li> or <td> without a
	// corresponding LIST or TABLE scope element on the stack.
	// <select> is not a scope for <option> elements, but we do that too for
	// symmetry and as an extra degree of safety against future spec changes.
	var wrapper *htmlElementTablesFreeWrapper
	if desc != TextNode && desc < len(t.freeWrappers) {
		wrapper = t.freeWrappers[desc]
	}
	if wrapper != nil {
		// The allowed containers are a bit set only as long as its highest
		// member.  For the select and list wrappers an ancestor past its end
		// is not among them: reading it as one left an option under a span,
		// a th or a ul, and a list item under a var, without its select or
		// list, and under a list the list's own item was implied instead,
		// which the next pass then wrapped (#492).  For a table part the
		// balancer returns to a table in scope before consulting this, and
		// its handling of parts in dropped tables was built on the old
		// reading, so an ancestor past the end still counts as allowed there.
		allowedContainer := wrapper.pastEndCountsAsAllowed
		if anc < len(wrapper.allowedContainers) {
			allowedContainer = wrapper.allowedContainers[anc]
		}
		if !allowedContainer {
			return wrapper.implied
		}
	}

	if desc != TextNode {
		implied := t.impliedElementTable.GetElementIndexList(anc, desc)
		// This handles the table case at least
		if len(implied) != 0 {
			return implied
		}
	}

	// If we require above that all <li>s appear in a <ul> or <ol> then
	// for symmetry, we require here that all content of a <ul> or <ol> appear
	// nested in a <li>.
	// This does not have the same security implications as the above, but is
	// symmetric.
	if (anc == t.olTag || anc == t.ulTag) && desc != t.liTag {
		return t.liTagArr
	}
	// A browser ignores the tags of most other children of a <select> and
	// keeps their text inside it.  Any child but an <option> is answered
	// with a list item so that the tag balancer, below a policy, nests it
	// inside the select the way a browser nests the text, instead of closing
	// the select for it.  That item is a synthetic container, not a browser
	// element and not an <option>: the balancer keeps it on its own stack
	// and never emits it, since an emitted one grew a list level on every
	// pass and hid the select from its end tag (#492).  With no policy below
	// to drop it the balancer skips the item and closes the select instead.
	if anc == t.selectTag && desc != t.optionTag {
		return t.liTagArr
	}
	return htmlElementTablesZeroInts
}

// htmlElementTablesGet returns the HTML metadata instance.
func htmlElementTablesGet() *HTMLElementTables {
	return htmlElementTablesCannedTables
}

// htmlElementTablesHTMLElementNamesCustomElementName is the placeholder name
// for any element name not defined by the HTML 6 specification or any
// similar document.
const htmlElementTablesHTMLElementNamesCustomElementName = "xcustom"

// HTMLElementTablesHTMLElementNames maps between element indices and element
// names.
type HTMLElementTablesHTMLElementNames struct {
	// CanonNames are the canonical element names by element index.
	CanonNames []string

	canonNameToIndex   map[string]int
	customElementIndex int
	// customChecked makes the first lookup panic when the names lack the
	// custom element name.
	customChecked sync.Once
}

// NewHTMLElementTablesHTMLElementNames indexes the given canonical names.
func NewHTMLElementTablesHTMLElementNames(canonNames []string) *HTMLElementTablesHTMLElementNames {
	names := &HTMLElementTablesHTMLElementNames{
		CanonNames:       append([]string(nil), canonNames...),
		canonNameToIndex: make(map[string]int, len(canonNames)),
	}
	for i, name := range names.CanonNames {
		names.canonNameToIndex[name] = i
	}
	names.customElementIndex = -1
	for i, name := range names.CanonNames {
		if name == htmlElementTablesHTMLElementNamesCustomElementName {
			names.customElementIndex = i
			break
		}
	}
	return names
}

// GetElementNameIndex is the index of the given element name or otherwise
// the index of the custom element name.  If the names lack the custom element
// name, which every table built from the browser probe has, the first call
// panics.
func (n *HTMLElementTablesHTMLElementNames) GetElementNameIndex(canonName string) int {
	n.customChecked.Do(func() {
		if n.customElementIndex < 0 {
			panic("Negative element index")
		}
	})
	if index, ok := n.canonNameToIndex[canonName]; ok {
		return index
	}
	return n.customElementIndex
}

// htmlElementTablesDenseElementBinaryMatrix yields a boolean given two
// element names.
type htmlElementTablesDenseElementBinaryMatrix struct {
	matrixLength int
	bits         []bool
}

// newHTMLElementTablesDenseElementBinaryMatrix wraps a copy of a square
// matrix stored row by row.  It panics if bits is not matrixLength squared
// long.
func newHTMLElementTablesDenseElementBinaryMatrix(bits []bool, matrixLength int) *htmlElementTablesDenseElementBinaryMatrix {
	if len(bits) != matrixLength*matrixLength {
		panic("Invalid matrix size")
	}
	return &htmlElementTablesDenseElementBinaryMatrix{
		matrixLength: matrixLength,
		bits:         append([]bool(nil), bits...),
	}
}

// get relates a, the first element name index, to b, the second.
func (m *htmlElementTablesDenseElementBinaryMatrix) get(a, b int) bool {
	if a < 0 || a >= m.matrixLength {
		panic("Invalid index for first element")
	}
	// b is not range-checked, so a negative b reads the end of the previous
	// row.
	return m.bits[a*m.matrixLength+b]
}

// String renders the matrix one row per line, '1' for a set bit and '.'
// otherwise.
func (m *htmlElementTablesDenseElementBinaryMatrix) String() string {
	var sb strings.Builder
	for j, k := 0, 0; j < m.matrixLength; j++ {
		if j != 0 {
			sb.WriteByte('\n')
		}
		for i := 0; i < m.matrixLength; i, k = i+1, k+1 {
			if m.bits[k] {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('.')
			}
		}
	}
	return sb.String()
}

// HTMLElementTablesDenseElementSet is a set of elements.
type HTMLElementTablesDenseElementSet struct {
	bits []bool
}

// NewHTMLElementTablesDenseElementSet wraps a copy of bits, indexed by
// element index.
func NewHTMLElementTablesDenseElementSet(bits []bool) *HTMLElementTablesDenseElementSet {
	return &HTMLElementTablesDenseElementSet{bits: append([]bool(nil), bits...)}
}

// Get is true iff the element at index i is in the set.
func (s *HTMLElementTablesDenseElementSet) Get(i int) bool {
	return s.bits[i]
}

// HTMLElementTablesSparseElementToElements maps element indices to sets of
// the same.
type HTMLElementTablesSparseElementToElements struct {
	arrs [][]int
}

// NewHTMLElementTablesSparseElementToElements takes arrays sorted by their
// zero-th element, which is the key, where each array from the first element
// on is a sorted set of values.  It returns an error if they are not sorted.
func NewHTMLElementTablesSparseElementToElements(arrs [][]int) (*HTMLElementTablesSparseElementToElements, error) {
	m := &HTMLElementTablesSparseElementToElements{arrs: make([][]int, len(arrs))}
	last := -1
	for i, arr := range arrs {
		arr = append([]int(nil), arr...)
		m.arrs[i] = arr
		if last >= arr[0] {
			return nil, errors.New("Non sorted array")
		}
		last = arr[0]
		lastVal := -1
		for _, val := range arr[1:] {
			if val <= lastVal {
				return nil, errors.New("Non sorted array")
			}
			lastVal = val
		}
	}
	return m, nil
}

func (m *HTMLElementTablesSparseElementToElements) get(key, value int) bool {
	row, ok := htmlElementTablesSearchByZeroth(m.arrs, key)
	if !ok {
		return false
	}
	arr := m.arrs[row]
	return htmlElementTablesBinSearchRange(arr, 1, len(arr), value)
}

// htmlElementTablesSearchByZeroth binary searches rows sorted by their
// zero-th element for the row whose zero-th element is key.
func htmlElementTablesSearchByZeroth(rows [][]int, key int) (int, bool) {
	i := sort.Search(len(rows), func(i int) bool { return rows[i][0] >= key })
	return i, i < len(rows) && rows[i][0] == key
}

// htmlElementTablesBinSearchRange reports whether value is in the sorted
// range arr[leftIncl:rightExcl].
func htmlElementTablesBinSearchRange(arr []int, leftIncl, rightExcl, value int) bool {
	lo, hi := leftIncl, rightExcl
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		el := arr[mid]
		delta := value - el
		if delta == 0 {
			return true
		} else if delta < 0 {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return false
}

// HTMLElementTablesSparseElementMultitable maps element to elements to lists
// of elements.
type HTMLElementTablesSparseElementMultitable struct {
	arrs [][][]int
}

// NewHTMLElementTablesSparseElementMultitable takes arrs such that
// arrs[aElementIndex] is nil or a slice, a, sorted by first element such
// that the first element is bIndex and the elements after the zero-th are
// the element indices that (aElementIndex, bElementIndex) map to in order.
// It returns an error if a row is out of order.
func NewHTMLElementTablesSparseElementMultitable(arrs [][][]int) (*HTMLElementTablesSparseElementMultitable, error) {
	m := &HTMLElementTablesSparseElementMultitable{arrs: make([][][]int, len(arrs))}
	for j, arrEl := range arrs {
		if arrEl == nil {
			m.arrs[j] = [][]int{}
			continue
		}
		rows := make([][]int, len(arrEl))
		for i, row := range arrEl {
			rows[i] = append([]int(nil), row...)
			if i != 0 && rows[i][0] <= rows[i-1][0] {
				return nil, errors.New("Illegal array state")
			}
		}
		m.arrs[j] = rows
	}
	return m, nil
}

// GetElementIndexList returns the element indices mapped to by
// (aIndex, bIndex).
func (m *HTMLElementTablesSparseElementMultitable) GetElementIndexList(aIndex, bIndex int) []int {
	if aIndex < len(m.arrs) {
		aArrs := m.arrs[aIndex]
		if bi, ok := htmlElementTablesSearchByZeroth(aArrs, bIndex); ok {
			return append([]int(nil), aArrs[bi][1:]...)
		}
	}
	return htmlElementTablesZeroInts
}

// HTMLElementTablesTextContentModel records, for each element, the kinds of
// character data it can contain.
type HTMLElementTablesTextContentModel struct {
	contentModelBitsPerElement []byte
}

// NewHTMLElementTablesTextContentModel wraps a copy of the packed
// HTMLElementTablesTextContentModelBit masks, indexed by element index.
func NewHTMLElementTablesTextContentModel(contentModelBitsPerElement []byte) *HTMLElementTablesTextContentModel {
	return &HTMLElementTablesTextContentModel{
		contentModelBitsPerElement: append([]byte(nil), contentModelBitsPerElement...),
	}
}

// CanContainComment reports whether <!--...--> parses to a comment when it
// appears in the identified element.
func (m *HTMLElementTablesTextContentModel) CanContainComment(elementIndex int) bool {
	return m.IsAllowed(elementIndex, HTMLElementTablesTextContentModelBitComments)
}

// CanContainEntities reports whether &amp; parses to an HTML character
// reference when it appears in the identified element.
func (m *HTMLElementTablesTextContentModel) CanContainEntities(elementIndex int) bool {
	return m.IsAllowed(elementIndex, HTMLElementTablesTextContentModelBitEntities)
}

// CanContainText reports whether parsing can produce an element with the
// given index that contains a text node.
func (m *HTMLElementTablesTextContentModel) CanContainText(elementIndex int) bool {
	return m.IsAllowed(elementIndex, HTMLElementTablesTextContentModelBitText)
}

// CanContainPlainText reports whether parsing can produce an element with
// the given index that contains a text node that has human readable text
// instead of script or style source code.
func (m *HTMLElementTablesTextContentModel) CanContainPlainText(elementIndex int) bool {
	return m.IsAllowed(elementIndex, HTMLElementTablesTextContentModelBitPlainText)
}

// IsRaw is true iff things that look like tags when they appear lexically
// within the element do in fact, parse to tags.
func (m *HTMLElementTablesTextContentModel) IsRaw(elementIndex int) bool {
	return m.IsAllowed(elementIndex, HTMLElementTablesTextContentModelBitRaw)
}

// IsUnended is true if parsing the element always proceeds to the end of
// input.
func (m *HTMLElementTablesTextContentModel) IsUnended(elementIndex int) bool {
	return m.IsAllowed(elementIndex, HTMLElementTablesTextContentModelBitUnended)
}

// IsAllowed is true if the given model bit is allowed within the element.
func (m *HTMLElementTablesTextContentModel) IsAllowed(elementIndex int, modelBit HTMLElementTablesTextContentModelBit) bool {
	return int(m.contentModelBitsPerElement[elementIndex])&modelBit.BitMask() != 0
}

// HTMLElementTablesTextContentModelBit describes properties of the content
// that could be added to an element as a result of a parse that includes its
// open tag.  Each value is its own bit mask.
type HTMLElementTablesTextContentModelBit int

// The text content model bits.
const (
	// HTMLElementTablesTextContentModelBitComments marks an element whose
	// content may include comments.
	HTMLElementTablesTextContentModelBitComments HTMLElementTablesTextContentModelBit = 1
	// HTMLElementTablesTextContentModelBitEntities marks an element whose
	// content may include character references.
	HTMLElementTablesTextContentModelBitEntities HTMLElementTablesTextContentModelBit = 2
	// HTMLElementTablesTextContentModelBitRaw marks an element that holds raw
	// text, which is not parsed as markup.
	HTMLElementTablesTextContentModelBitRaw HTMLElementTablesTextContentModelBit = 4
	// HTMLElementTablesTextContentModelBitText marks an element that may
	// contain text.
	HTMLElementTablesTextContentModelBitText HTMLElementTablesTextContentModelBit = 8
	// HTMLElementTablesTextContentModelBitUnended marks an element that, once
	// open, runs to the end of the document.
	HTMLElementTablesTextContentModelBitUnended HTMLElementTablesTextContentModelBit = 16
	// HTMLElementTablesTextContentModelBitPlainText marks an element that may
	// contain human readable text rather than script or style source code.
	HTMLElementTablesTextContentModelBitPlainText HTMLElementTablesTextContentModelBit = 32
)

// BitMask is the single bit used internally to identify the bit in packed
// form.
func (b HTMLElementTablesTextContentModelBit) BitMask() int {
	return int(b)
}

// HTMLElementTablesUnpack unpacks a []bool of the given length from 32-bit
// words, least significant bit first.  This keeps largish tables compact in
// generated source.
func HTMLElementTablesUnpack(packed []int32, length int) []bool {
	bools := make([]bool, length)
	for i := range bools {
		bools[i] = uint32(packed[i>>5])&(1<<uint(i&0x1f)) != 0
	}
	return bools
}
